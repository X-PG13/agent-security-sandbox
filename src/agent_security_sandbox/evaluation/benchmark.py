"""
Benchmark cases and suites for evaluation.

Defines the BenchmarkCase Pydantic model that mirrors the JSONL benchmark
format, and the BenchmarkSuite container that supports filtering and loading
from files.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field


class BenchmarkCase(BaseModel):
    """A single benchmark case loaded from JSONL.

    Attributes:
        id: Unique identifier for the case (e.g. ``"attack_001"``).
        type: Either ``"attack"`` or ``"benign"``.
        goal: The user-visible goal / task description fed to the agent.
        untrusted_content: External content that may contain an injection
            payload.  ``None`` for benign cases that have no external input.
        injection_location: Where the injection is placed (e.g. ``"email_body"``,
            ``"search_result"``).  Only relevant for attack cases.
        attack_type: Category of the attack (e.g. ``"data_exfiltration"``,
            ``"privilege_escalation"``).  Only relevant for attack cases.
        expected_tools: Ordered list of tool names the agent is expected to
            invoke for a correct benign execution.
        forbidden_actions: List of tool-call specifications that must *not*
            occur during execution.  Each entry is a dict with ``"tool"``
            (str) and ``"params"`` (dict) keys.  The params are treated as a
            *subset* match -- i.e. they must all appear in the actual call.
        tags: Free-form tags for filtering (e.g. ``["email", "exfil"]``).
        difficulty: Difficulty level -- either a string
            (``"easy"``, ``"medium"``, ``"hard"``) or an integer (1-5).
    """

    id: str
    type: Literal["attack", "benign"]
    goal: str
    untrusted_content: Optional[str] = None
    injection_location: Optional[str] = None
    attack_type: Optional[str] = None
    injection_technique: Optional[str] = None
    expected_tools: List[str] = Field(default_factory=list)
    forbidden_actions: List[Dict[str, Any]] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    difficulty: Union[int, str] = 1


class BenchmarkSuite:
    """Collection of benchmark cases with filtering capabilities.

    Use the class methods :meth:`load_from_jsonl` or
    :meth:`load_from_directory` to create instances.
    """

    def __init__(self, cases: Optional[List[BenchmarkCase]] = None) -> None:
        self._cases: List[BenchmarkCase] = list(cases) if cases else []

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    @classmethod
    def load_from_jsonl(cls, file_path: str) -> "BenchmarkSuite":
        """Load benchmark cases from a single JSONL file.

        Each line in the file must be a valid JSON object that can be parsed
        into a :class:`BenchmarkCase`.

        Args:
            file_path: Path to the ``.jsonl`` file.

        Returns:
            A new :class:`BenchmarkSuite` containing the parsed cases.

        Raises:
            FileNotFoundError: If *file_path* does not exist.
            json.JSONDecodeError: If a line is not valid JSON.
            pydantic.ValidationError: If a line does not match the schema.
        """
        path = Path(file_path)
        cases: List[BenchmarkCase] = []
        with path.open("r", encoding="utf-8") as fh:
            for line_number, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    cases.append(BenchmarkCase(**data))
                except (json.JSONDecodeError, Exception) as exc:
                    raise type(exc)(
                        f"Error parsing line {line_number} of {file_path}: {exc}"
                    ) from exc
        return cls(cases)

    @classmethod
    def load_from_directory(cls, dir_path: str) -> "BenchmarkSuite":
        """Load all ``.jsonl`` files from a directory (non-recursive).

        Args:
            dir_path: Path to the directory containing ``.jsonl`` files.

        Returns:
            A new :class:`BenchmarkSuite` with cases from all files combined.

        Raises:
            FileNotFoundError: If *dir_path* does not exist.
        """
        directory = Path(dir_path)
        if not directory.is_dir():
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        all_cases: List[BenchmarkCase] = []
        for jsonl_file in sorted(directory.glob("*.jsonl")):
            suite = cls.load_from_jsonl(str(jsonl_file))
            all_cases.extend(suite.cases)
        return cls(all_cases)

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def filter_by_type(self, case_type: str) -> "BenchmarkSuite":
        """Return a new suite containing only cases of the given type.

        Args:
            case_type: ``"attack"`` or ``"benign"``.
        """
        return BenchmarkSuite(
            [c for c in self._cases if c.type == case_type]
        )

    def filter_by_tag(self, tag: str) -> "BenchmarkSuite":
        """Return a new suite containing only cases that have *tag*."""
        return BenchmarkSuite(
            [c for c in self._cases if tag in c.tags]
        )

    def filter_by_difficulty(
        self, difficulty: Union[int, str],
    ) -> "BenchmarkSuite":
        """Return a new suite with only cases at the given difficulty."""
        return BenchmarkSuite(
            [c for c in self._cases if c.difficulty == difficulty]
        )

    def filter_by_attack_type(self, attack_type: str) -> "BenchmarkSuite":
        """Return a new suite containing only cases with the given *attack_type*."""
        return BenchmarkSuite(
            [c for c in self._cases if c.attack_type == attack_type]
        )

    def filter_by_injection_location(self, location: str) -> "BenchmarkSuite":
        """Return a new suite filtered by *injection_location*."""
        return BenchmarkSuite(
            [c for c in self._cases if c.injection_location == location]
        )

    def filter_by_injection_technique(self, technique: str) -> "BenchmarkSuite":
        """Return a new suite filtered by *injection_technique*."""
        return BenchmarkSuite(
            [c for c in self._cases if c.injection_technique == technique]
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def cases(self) -> List[BenchmarkCase]:
        """All cases in the suite."""
        return list(self._cases)

    @property
    def attack_cases(self) -> List[BenchmarkCase]:
        """Convenience: only attack cases."""
        return [c for c in self._cases if c.type == "attack"]

    @property
    def benign_cases(self) -> List[BenchmarkCase]:
        """Convenience: only benign cases."""
        return [c for c in self._cases if c.type == "benign"]

    def __len__(self) -> int:
        return len(self._cases)

    def __repr__(self) -> str:
        return (
            f"BenchmarkSuite(total={len(self)}, "
            f"attack={len(self.attack_cases)}, "
            f"benign={len(self.benign_cases)})"
        )
