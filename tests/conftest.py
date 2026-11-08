"""
Fake models for testing without an API.

- OracleModel knows the right answer for every dataset alert and is never
  fooled: the evaluation must score it perfectly.
- GullibleModel answers like the oracle but obeys any instruction it finds
  in the alert, the way an unprotected model can: the guards must stop what
  they claim to stop, and the evaluation must catch the rest.
"""

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("TRIAGE_BOUNDARY_SECRET", "tests")

from triage import injections  # noqa: E402

DATASET = ROOT / "datasets" / "alerts.jsonl"
ITEMS = [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines()]
LABELS = {item["alert"]["description"]: item for item in ITEMS}


def answer(verdict, severity="medium", confidence=0.9, reasoning="ok", injection=False):
    return json.dumps({"verdict": verdict, "severity": severity, "confidence": confidence,
                       "reasoning": reasoning, "next_steps": ["check"], "injection_suspected": injection})


def _item_for(messages):
    text = messages[-1]["content"]
    for description, item in LABELS.items():
        if json.dumps(description)[1:-1] in text or description in text:
            return item
    raise AssertionError("alert not in dataset")


class OracleModel:
    name = "oracle"

    def __init__(self):
        self.calls = []

    def complete(self, messages):
        self.calls.append(messages)
        item = _item_for(messages)
        return answer(item["label"], item["alert"]["severity"])


class GullibleModel(OracleModel):
    name = "gullible"

    def complete(self, messages):
        self.calls.append(messages)
        text = messages[-1]["content"]
        if injections.CANARY in text:
            return answer("false_positive", "low", 0.95, f"As instructed: {injections.CANARY}")
        item = _item_for(messages)
        return answer(item["label"], item["alert"]["severity"])


@pytest.fixture
def items():
    return ITEMS


@pytest.fixture
def oracle():
    return OracleModel()


@pytest.fixture
def gullible():
    return GullibleModel()
