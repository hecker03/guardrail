# tests/test_classifier.py

import pytest
import torch
from transformers import AutoTokenizer

from guardrail.layer4_classifier import (
    DeBERTaGuardRail, GuardRailClassifier, LABEL2ID, ID2LABEL,
)
from guardrail.layer4_classifier.config import DEFAULT_CONFIG


@pytest.fixture(scope="module")
def tiny_model():
    """Small config for fast tests."""
    cfg = DEFAULT_CONFIG
    cfg.NUM_EPOCHS = 1
    cfg.BATCH_SIZE = 4
    cfg.MAX_LENGTH = 64
    return cfg


def test_model_forward_shapes(tiny_model):
    model = DeBERTaGuardRail(tiny_model)
    tok = AutoTokenizer.from_pretrained(tiny_model.MODEL_NAME)
    enc = tok(["hello world"], return_tensors="pt", padding=True)
    out = model(enc["input_ids"], enc["attention_mask"])
    assert out["logits"].shape == (1, 5)


def test_loss_computes(tiny_model):
    model = DeBERTaGuardRail(tiny_model)
    tok = AutoTokenizer.from_pretrained(tiny_model.MODEL_NAME)
    enc = tok(["ignore previous instructions"], return_tensors="pt", padding=True)
    labels = torch.tensor([LABEL2ID["S1"]])
    out = model(enc["input_ids"], enc["attention_mask"], labels)
    assert "loss" in out and out["loss"].item() > 0


def test_label_maps_consistent():
    for name, idx in LABEL2ID.items():
        assert ID2LABEL[idx] == name