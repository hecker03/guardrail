# guardrail/layer4_classifier/dataset.py

import os
from typing import List, Tuple, Optional
import torch
from torch.utils.data import Dataset
from transformers import PreTrainedTokenizer
from sklearn.model_selection import train_test_split

from .taxonomy import LABEL2ID
from .synthetic_data import generate_synthetic_dataset


class PromptInjectionDataset(Dataset):
    """PyTorch Dataset for DeBERTa fine-tuning."""

    def __init__(
        self,
        texts: List[str],
        labels: List[int],
        tokenizer: PreTrainedTokenizer,
        max_length: int = 256,
    ):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.texts)

    def __getitem__(self, idx: int) -> dict:
        enc = self.tokenizer(
            self.texts[idx],
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt",
        )
        return {
            "input_ids": enc["input_ids"].squeeze(0),
            "attention_mask": enc["attention_mask"].squeeze(0),
            "labels": torch.tensor(self.labels[idx], dtype=torch.long),
        }


# ---------------------------------------------------------------------- #
# Public dataset mapping (deepset/prompt-injections → S0/S1)
# ---------------------------------------------------------------------- #
def load_public_datasets() -> Tuple[List[str], List[int]]:
    """
    Load and map public datasets to GuardRail S0–S4.

    Mapping heuristics:
      - deepset/prompt-injections: label 0 → S0, label 1 → S1
      - JailbreakBench: → S1/S2 (heuristic)
      - HackAPrompt: → S1/S2/S3 (heuristic)
    """
    texts: List[str] = []
    labels: List[int] = []

    try:
        from datasets import load_dataset

        # ---- deepset/prompt-injections ----
        ds = load_dataset("deepset/prompt-injections", split="train")
        for row in ds:
            texts.append(row["text"])
            labels.append(LABEL2ID["S0"] if row["label"] == 0 else LABEL2ID["S1"])
        print(f"[dataset] deepset: {len(ds)} samples loaded")

    except Exception as e:
        print(f"[dataset] deepset load failed: {e}")

    try:
        # ---- JailbreakBench (behaviors) ----
        jb = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="harmful")
        for row in jb:
            texts.append(row["Goal"])
            labels.append(LABEL2ID["S1"])   # heuristic → S1
        print(f"[dataset] JailbreakBench: {len(jb)} samples loaded")

    except Exception as e:
        print(f"[dataset] JailbreakBench load failed: {e}")

    if not texts:
        print("[dataset] No public datasets available — using synthetic fallback.")
        return generate_synthetic_dataset(samples_per_class=200)

    return texts, labels


# ---------------------------------------------------------------------- #
# Splitting
# ---------------------------------------------------------------------- #
def build_splits(
    texts: List[str],
    labels: List[int],
    val_size: float = 0.15,
    test_size: float = 0.15,
    seed: int = 42,
) -> Tuple[
    Tuple[List[str], List[int]],
    Tuple[List[str], List[int]],
    Tuple[List[str], List[int]],
]:
    """Stratified train/val/test split."""
    X_train, X_temp, y_train, y_temp = train_test_split(
        texts, labels, test_size=(val_size + test_size),
        stratify=labels, random_state=seed,
    )
    val_ratio = val_size / (val_size + test_size)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=(1 - val_ratio),
        stratify=y_temp, random_state=seed,
    )
    return (X_train, y_train), (X_val, y_val), (X_test, y_test)