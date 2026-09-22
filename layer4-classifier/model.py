# guardrail/layer4_classifier/model.py

import torch
import torch.nn as nn
from transformers import AutoModel, AutoConfig

from .config import ClassifierConfig, DEFAULT_CONFIG
from .taxonomy import NUM_LABELS


class DeBERTaGuardRail(nn.Module):
    """
    Fine-tuned DeBERTa-v3 with a classification head for S0–S4.

    Architecture:
        DeBERTa-v3-base encoder → [CLS] pooling → Dropout → Linear(768 → 5)
    """

    def __init__(self, config: ClassifierConfig = DEFAULT_CONFIG):
        super().__init__()
        self.cfg = config

        hf_config = AutoConfig.from_pretrained(
            config.MODEL_NAME,
            num_labels=NUM_LABELS,
            hidden_dropout_prob=config.DROPOUT,
            attention_probs_dropout_prob=config.DROPOUT,
        )
        self.encoder = AutoModel.from_pretrained(
            config.MODEL_NAME, config=hf_config,
        )
        hidden_size = hf_config.hidden_size     # 768 for base

        self.dropout = nn.Dropout(config.DROPOUT)
        self.classifier = nn.Linear(hidden_size, NUM_LABELS)

        # Initialize head
        nn.init.normal_(self.classifier.weight, std=0.02)
        nn.init.zeros_(self.classifier.bias)

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        labels: torch.Tensor = None,
    ) -> dict:
        outputs = self.encoder(
            input_ids=input_ids,
            attention_mask=attention_mask,
        )
        # Mean-pool over non-padding tokens (more robust than [CLS] for DeBERTa)
        last_hidden = outputs.last_hidden_state                # (B, L, H)
        mask = attention_mask.unsqueeze(-1).float()            # (B, L, 1)
        pooled = (last_hidden * mask).sum(1) / mask.sum(1).clamp(min=1e-9)

        logits = self.classifier(self.dropout(pooled))         # (B, 5)

        result = {"logits": logits}
        if labels is not None:
            result["loss"] = self._loss(logits, labels)
        return result

    def _loss(self, logits: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """Focal loss — handles class imbalance better than plain CE."""
        gamma = self.cfg.FOCAL_LOSS_GAMMA
        ce = nn.functional.cross_entropy(logits, labels, reduction="none")
        pt = torch.exp(-ce)
        focal = ((1 - pt) ** gamma) * ce
        return focal.mean()