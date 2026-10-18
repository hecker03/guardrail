# guardrail/layer4_classifier/config.py

from dataclasses import dataclass


@dataclass
class ClassifierConfig:
    """Configuration for Layer 4 Neural Classifier."""

    # Model architecture
    MODEL_NAME: str = "microsoft/deberta-v3-base"
    DROPOUT: float = 0.1
    FOCAL_LOSS_GAMMA: float = 2.0

    # Training parameters
    SEED: int = 42
    DEVICE: str = "cuda"
    MAX_LENGTH: int = 512
    BATCH_SIZE: int = 16
    WEIGHT_DECAY: float = 0.01
    LEARNING_RATE: float = 2e-5
    GRAD_ACCUM_STEPS: int = 1
    NUM_EPOCHS: int = 3
    WARMUP_RATIO: float = 0.1
    FP16: bool = True
    MAX_GRAD_NORM: float = 1.0
    CHECKPOINT_DIR: str = "./checkpoints/deberta_guardrail"

    # Inference & Explainability thresholds
    CONFIDENCE_THRESHOLD: float = 0.70
    LIME_NUM_FEATURES: int = 10
    LIME_NUM_SAMPLES: int = 50


DEFAULT_CONFIG = ClassifierConfig()
