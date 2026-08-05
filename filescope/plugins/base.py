from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from filescope.core.models import AnalysisResult


class AnalysisPlugin(ABC):
    name = "Unnamed plugin"

    @abstractmethod
    def supports(self, path: Path, header: bytes, detected_type: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def analyze(self, result: AnalysisResult, header: bytes) -> None:
        raise NotImplementedError
