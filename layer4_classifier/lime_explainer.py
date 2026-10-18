# guardrail/layer4_classifier/lime_explainer.py

import numpy as np
import torch
from typing import List, Dict, Tuple
from lime.lime_text import LimeTextExplainer

from .config import DEFAULT_CONFIG
from .taxonomy import ID2LABEL


class LIMETokenExplainer:
    """
    Token-level LIME explanations for GuardRail's DeBERTa classifier.

    Produces a ranked list of tokens that most influenced the predicted class.
    """

    def __init__(self, model, tokenizer, config=DEFAULT_CONFIG, device="cpu"):
        self.model = model
        self.tokenizer = tokenizer
        self.cfg = config
        self.device = device

        self.explainer = LimeTextExplainer(
            class_names=[ID2LABEL[i] for i in range(len(ID2LABEL))],
            split_expression=r"\s+",
            random_state=42,
        )

    # ------------------------------------------------------------------ #
    # Probability function for LIME
    # ------------------------------------------------------------------ #
    def _predict_proba(self, texts: List[str]) -> np.ndarray:
        self.model.eval()
        all_probs = []
        with torch.no_grad():
            for i in range(0, len(texts), self.cfg.BATCH_SIZE):
                batch = texts[i:i + self.cfg.BATCH_SIZE]
                enc = self.tokenizer(
                    batch,
                    truncation=True,
                    padding=True,
                    max_length=self.cfg.MAX_LENGTH,
                    return_tensors="pt",
                ).to(self.device)
                logits = self.model(
                    enc["input_ids"], enc["attention_mask"]
                )["logits"]
                probs = torch.softmax(logits, dim=-1).cpu().numpy()
                all_probs.append(probs)
        return np.vstack(all_probs)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def explain(
        self,
        text: str,
        top_labels: int = 1,
    ) -> Dict:
        """
        Generate LIME explanation for a single input.

        Returns:
            {
              "text": str,
              "predicted_label": str,
              "confidence": float,
              "explanations": {
                  "S1": [("ignore", 0.42), ("previous", 0.31), ...],
                  ...
              }
            }
        """
        probs = self._predict_proba([text])[0]
        pred_id = int(np.argmax(probs))
        pred_label = ID2LABEL[pred_id]

        num_features = getattr(self.cfg, "LIME_NUM_FEATURES", 10)
        num_samples = getattr(self.cfg, "LIME_NUM_SAMPLES", 50)
        exp = self.explainer.explain_instance(
            text,
            self._predict_proba,
            num_features=num_features,
            num_samples=num_samples,
            top_labels=top_labels,
        )

        explanations: Dict[str, List[Tuple[str, float]]] = {}
        for label_id in exp.available_labels():
            label_name = ID2LABEL[label_id]
            explanations[label_name] = exp.as_list(label=label_id)

        return {
            "text": text,
            "predicted_label": pred_label,
            "confidence": float(probs[pred_id]),
            "all_probabilities": {
                ID2LABEL[i]: float(probs[i]) for i in range(len(probs))
            },
            "explanations": explanations,
        }

    # ------------------------------------------------------------------ #
    # HTML rendering (for React dashboard)
    # ------------------------------------------------------------------ #
    def explain_html(self, text: str) -> str:
        exp = self.explain(text)
        pred = exp["predicted_label"]
        label_id = [k for k, v in ID2LABEL.items() if v == pred][0]

        num_features = getattr(self.cfg, "LIME_NUM_FEATURES", 10)
        num_samples = getattr(self.cfg, "LIME_NUM_SAMPLES", 50)
        lime_exp = self.explainer.explain_instance(
            text,
            self._predict_proba,
            num_features=num_features,
            num_samples=num_samples,
            top_labels=1,
        )
        return lime_exp.as_html()