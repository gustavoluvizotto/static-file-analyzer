import os
from pathlib import Path

import pytest

from make_corpus import build_corpus

REPO = Path(__file__).resolve().parent.parent
RULES_DIR = REPO / "rules"

is_root = hasattr(os, "geteuid") and os.geteuid() == 0


@pytest.fixture
def corpus(tmp_path):
    """A freshly generated corpus; returns its root (with good/ and bad/)."""
    root = tmp_path / "corpus"
    build_corpus(root)
    yield root
    unreadable = root / "good" / "unreadable.txt"
    if unreadable.exists():
        unreadable.chmod(0o644)  # let pytest clean tmp_path
