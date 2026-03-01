"""
Defense Registry -- Factory functions for creating defense strategies.

Provides two entry points:

* ``create_defense(defense_id, config, llm_client)`` -- create a single
  defense by its ID (``"D0"`` .. ``"D4"``).
* ``load_defenses_from_yaml(yaml_path)`` -- load all defense definitions
  from a YAML configuration file and return a mapping of ID to strategy.
"""
from pathlib import Path
from typing import Any, Dict

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from .base import DefenseStrategy
from .composite import CompositeDefense
from .d0_baseline import BaselineDefense
from .d1_spotlighting import SpotlightingDefense
from .d2_policy_gate import PolicyGateDefense
from .d3_task_alignment import TaskAlignmentDefense
from .d4_reexecution import ReExecutionDefense

# Map defense IDs to their implementation classes.
_DEFENSE_CLASSES: Dict[str, type] = {
    "D0": BaselineDefense,
    "D1": SpotlightingDefense,
    "D2": PolicyGateDefense,
    "D3": TaskAlignmentDefense,
    "D4": ReExecutionDefense,
}


def create_defense(
    defense_id: str,
    config: Dict[str, Any] | None = None,
    llm_client: Any = None,
) -> DefenseStrategy:
    """Create a single defense strategy by its ID.

    Args:
        defense_id: One of ``"D0"``, ``"D1"``, ``"D2"``, ``"D3"``, ``"D4"``.
        config: Optional configuration dictionary for the defense.
        llm_client: Optional ``LLMClient`` instance (used by D3 and D4).

    Returns:
        An instantiated ``DefenseStrategy``.

    Raises:
        ValueError: If *defense_id* is not recognised.
    """
    defense_id_upper = defense_id.upper()

    cls = _DEFENSE_CLASSES.get(defense_id_upper)
    if cls is None:
        available = ", ".join(sorted(_DEFENSE_CLASSES.keys()))
        raise ValueError(
            f"Unknown defense ID '{defense_id}'. "
            f"Available defenses: {available}"
        )

    # D3 and D4 accept an optional llm_client argument.
    if defense_id_upper in ("D3", "D4"):
        return cls(config=config, llm_client=llm_client)

    return cls(config=config)


def create_composite_defense(
    defense_ids: list[str],
    configs: Dict[str, Dict[str, Any]] | None = None,
    llm_client: Any = None,
) -> CompositeDefense:
    """Create a composite defense from a list of defense IDs.

    Args:
        defense_ids: List of defense IDs (e.g. ``["D1", "D2", "D3"]``).
        configs: Mapping of defense ID to its config dict.  If a defense
            ID is not present in *configs* an empty config is used.
        llm_client: Optional ``LLMClient`` passed to defenses that need it.

    Returns:
        A ``CompositeDefense`` wrapping all requested strategies.
    """
    configs = configs or {}
    strategies = [
        create_defense(did, config=configs.get(did.upper(), {}), llm_client=llm_client)
        for did in defense_ids
    ]
    return CompositeDefense(strategies)


def load_defenses_from_yaml(
    yaml_path: str | Path,
    llm_client: Any = None,
) -> Dict[str, DefenseStrategy]:
    """Load all defenses defined in a YAML configuration file.

    The YAML file is expected to have the structure used by
    ``config/defenses.yaml``::

        defenses:
          D0:
            name: "Baseline (No Defense)"
            config: {}
          D1:
            name: "Spotlighting"
            config:
              delimiter_start: "..."
              ...

        combinations:
          D1_D2:
            defenses: ["D1", "D2"]

    Args:
        yaml_path: Path to the YAML configuration file.
        llm_client: Optional ``LLMClient`` passed to defenses that need it.

    Returns:
        A dictionary mapping defense IDs (e.g. ``"D0"``, ``"D1_D2"``) to
        instantiated ``DefenseStrategy`` objects.

    Raises:
        ImportError: If PyYAML is not installed.
        FileNotFoundError: If *yaml_path* does not exist.
    """
    if not YAML_AVAILABLE:
        raise ImportError(
            "PyYAML is required to load defenses from YAML.  "
            "Install it with: pip install pyyaml"
        )

    yaml_path = Path(yaml_path)
    if not yaml_path.exists():
        raise FileNotFoundError(f"Defense config not found: {yaml_path}")

    with open(yaml_path, "r") as fh:
        raw = yaml.safe_load(fh)

    result: Dict[str, DefenseStrategy] = {}

    # Individual defenses
    defenses_section = raw.get("defenses", {})
    defense_configs: Dict[str, Dict[str, Any]] = {}

    for defense_id, defense_def in defenses_section.items():
        if not defense_def.get("enabled", True):
            continue
        config = defense_def.get("config", {})
        defense_configs[defense_id] = config
        result[defense_id] = create_defense(
            defense_id, config=config, llm_client=llm_client
        )

    # Composite / combination defenses
    combinations_section = raw.get("combinations", {})
    for combo_id, combo_def in (combinations_section or {}).items():
        combo_defense_ids = combo_def.get("defenses", [])
        if not combo_defense_ids:
            continue
        result[combo_id] = create_composite_defense(
            combo_defense_ids,
            configs=defense_configs,
            llm_client=llm_client,
        )

    return result
