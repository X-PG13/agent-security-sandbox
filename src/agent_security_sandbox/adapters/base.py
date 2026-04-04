"""Abstract base class for external benchmark adapters."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from ..evaluation.benchmark import BenchmarkCase, BenchmarkSuite


class BenchmarkAdapter(ABC):
    """Converts external benchmark formats into ASB ``BenchmarkCase`` objects.

    Subclasses implement :meth:`load` to read from a file or directory
    and return a list of ASB-compatible cases.
    """

    @abstractmethod
    def load(self, path: str | Path) -> List[BenchmarkCase]:
        """Load cases from the external benchmark at *path*.

        Args:
            path: Path to the benchmark file or directory.

        Returns:
            A list of ``BenchmarkCase`` instances.
        """
        ...

    def load_as_suite(self, path: str | Path) -> BenchmarkSuite:
        """Convenience: load and wrap in a ``BenchmarkSuite``."""
        cases = self.load(path)
        return BenchmarkSuite(cases)

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the external benchmark."""
        ...
