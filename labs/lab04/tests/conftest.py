"""Спільні заготовки для тестів"""

import json
from pathlib import Path

import pytest

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Заборонити справжні запити Requests і прибрати успадкований ключ"""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def sample_payload():
    """Нова копія синтетичної відповіді NVD для кожного тесту"""
    with SAMPLE_PATH.open(encoding="utf-8") as file:
        return json.load(file)
