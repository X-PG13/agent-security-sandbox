"""Defense strategies for protecting agents against prompt injection."""

from .base import DefenseDecision, DefenseResult, DefenseStrategy
from .composite import CompositeDefense
from .d0_baseline import BaselineDefense
from .d1_spotlighting import SpotlightingDefense
from .d2_policy_gate import PolicyGateDefense
from .d3_task_alignment import TaskAlignmentDefense
from .d4_reexecution import ReExecutionDefense
from .d5_sandwich import SandwichDefense
from .registry import create_composite_defense, create_defense, load_defenses_from_yaml

__all__ = [
    "DefenseStrategy",
    "DefenseResult",
    "DefenseDecision",
    "BaselineDefense",
    "SpotlightingDefense",
    "PolicyGateDefense",
    "TaskAlignmentDefense",
    "ReExecutionDefense",
    "SandwichDefense",
    "CompositeDefense",
    "create_defense",
    "create_composite_defense",
    "load_defenses_from_yaml",
]
