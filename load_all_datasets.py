# scripts/load_all_datasets.py

from datasets import load_dataset
import pandas as pd

DATASETS = {
    # S0 — Benign
    "lmsys_benign": ("lmsys/lmsys-chat-1m", "train", "conversation"),
    "hh_rlhf": ("Anthropic/hh-rlhf", "train", "chosen"),

    # S1 — Override
    "deepset": ("deepset/prompt-injections", "train", "text"),
    "jailbreak_llms": ("verazuo/jailbreak_llms", "train", "prompt"),

    # S2 — Role Hijack
    "in_the_wild": ("TrustAIRLab/in-the-wild-jailbreak-prompts", "train", "prompt"),
    "chatgpt_jailbreak": ("rubend18/ChatGPT-Jailbreak-Prompts", "train", "Prompt"),

    # S3 — Context Injection
    "ragtruth": ("ParticleMedia/RAGTruth", "train", "output"),

    # S4 — Exfiltration
    "agentharm": ("ai-safety-institute/AgentHarm", "test_public", "prompt"),

    # Multilingual
    "multijail": ("DAMO-NLP-SG/MultiJail", "train", "prompt"),
}


def load_all():
    loaded = {}
    for name, (path, split, col) in DATASETS.items():
        try:
            ds = load_dataset(path, split=split)
            loaded[name] = ds
            print(f"✅ {name}: {len(ds)} rows (col: {col})")
        except Exception as e:
            print(f"❌ {name}: {e}")
    return loaded


if __name__ == "__main__":
    load_all()