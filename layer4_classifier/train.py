# guardrail/layer4_classifier/train.py

import os
import json
import numpy as np
import torch
from torch.utils.data import DataLoader
from transformers import AutoTokenizer, get_linear_schedule_with_warmup
from sklearn.metrics import classification_report, f1_score
from tqdm import tqdm

from .config import DEFAULT_CONFIG
from .model import DeBERTaGuardRail
from .dataset import (
    PromptInjectionDataset, load_public_datasets, build_splits,
)
from .taxonomy import ID2LABEL, LABEL2ID


def set_seed(seed: int):
    import random
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def evaluate(model, loader, device):
    model.eval()
    all_preds, all_labels = [], []
    with torch.no_grad():
        for batch in loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)
            out = model(input_ids, attention_mask)
            preds = out["logits"].argmax(-1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
    f1 = f1_score(all_labels, all_preds, average="macro")
    return f1, all_labels, all_preds


def train(config=DEFAULT_CONFIG):
    set_seed(config.SEED)
    device = torch.device(
        config.DEVICE if torch.cuda.is_available() else "cpu"
    )
    print(f"[train] device={device}")

    # ---- 1) Data ----
    texts, labels = load_public_datasets()
    print(f"[train] total samples: {len(texts)}")
    (X_tr, y_tr), (X_val, y_val), (X_te, y_te) = build_splits(texts, labels)

    # ---- 2) Tokenizer ----
    tokenizer = AutoTokenizer.from_pretrained(config.MODEL_NAME)

    train_ds = PromptInjectionDataset(X_tr, y_tr, tokenizer, config.MAX_LENGTH)
    val_ds = PromptInjectionDataset(X_val, y_val, tokenizer, config.MAX_LENGTH)
    test_ds = PromptInjectionDataset(X_te, y_te, tokenizer, config.MAX_LENGTH)

    train_loader = DataLoader(train_ds, batch_size=config.BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=config.BATCH_SIZE)
    test_loader = DataLoader(test_ds, batch_size=config.BATCH_SIZE)

    # ---- 3) Model ----
    model = DeBERTaGuardRail(config).to(device)

    # ---- 4) Optimizer + Scheduler ----
    no_decay = ["bias", "LayerNorm.weight"]
    params = [
        {"params": [p for n, p in model.named_parameters()
                    if not any(nd in n for nd in no_decay)],
         "weight_decay": config.WEIGHT_DECAY},
        {"params": [p for n, p in model.named_parameters()
                    if any(nd in n for nd in no_decay)],
         "weight_decay": 0.0},
    ]
    optimizer = torch.optim.AdamW(params, lr=config.LEARNING_RATE)

    total_steps = (
        len(train_loader) // config.GRAD_ACCUM_STEPS
    ) * config.NUM_EPOCHS
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(total_steps * config.WARMUP_RATIO),
        num_training_steps=total_steps,
    )

    scaler = torch.cuda.amp.GradScaler(enabled=config.FP16 and device.type == "cuda")

    # ---- 5) Training loop ----
    best_f1 = 0.0
    os.makedirs(config.CHECKPOINT_DIR, exist_ok=True)

    for epoch in range(config.NUM_EPOCHS):
        model.train()
        epoch_loss = 0.0
        optimizer.zero_grad()

        pbar = tqdm(train_loader, desc=f"Epoch {epoch+1}/{config.NUM_EPOCHS}")
        for step, batch in enumerate(pbar):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels_b = batch["labels"].to(device)

            with torch.cuda.amp.autocast(enabled=config.FP16 and device.type == "cuda"):
                out = model(input_ids, attention_mask, labels_b)
                loss = out["loss"] / config.GRAD_ACCUM_STEPS

            scaler.scale(loss).backward()
            epoch_loss += loss.item() * config.GRAD_ACCUM_STEPS

            if (step + 1) % config.GRAD_ACCUM_STEPS == 0:
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), config.MAX_GRAD_NORM)
                scaler.step(optimizer)
                scaler.update()
                scheduler.step()
                optimizer.zero_grad()

            pbar.set_postfix(loss=f"{epoch_loss/(step+1):.4f}")

        # ---- Validation ----
        f1, _, _ = evaluate(model, val_loader, device)
        print(f"[epoch {epoch+1}] val_macro_f1={f1:.4f}")

        if f1 > best_f1:
            best_f1 = f1
            model.encoder.save_pretrained(config.CHECKPOINT_DIR)
            tokenizer.save_pretrained(config.CHECKPOINT_DIR)
            torch.save(model.state_dict(), os.path.join(config.CHECKPOINT_DIR, "head.pt"))
            print(f"[train] saved best model (f1={best_f1:.4f})")

    # ---- 6) Test ----
    model.load_state_dict(torch.load(os.path.join(config.CHECKPOINT_DIR, "head.pt")))
    f1, y_true, y_pred = evaluate(model, test_loader, device)
    print(f"[test] macro_f1={f1:.4f}")
    print(classification_report(
        y_true, y_pred,
        target_names=[ID2LABEL[i] for i in range(len(ID2LABEL))],
    ))

    # ---- 7) Save training metadata ----
    with open(os.path.join(config.CHECKPOINT_DIR, "train_meta.json"), "w") as f:
        json.dump({
            "best_val_f1": best_f1,
            "test_macro_f1": f1,
            "label_map": LABEL2ID,
            "model_name": config.MODEL_NAME,
        }, f, indent=2)


if __name__ == "__main__":
    train()