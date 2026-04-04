"""Detailed tests for the defense registry module."""
import textwrap

import pytest

from agent_security_sandbox.defenses.composite import CompositeDefense
from agent_security_sandbox.defenses.d0_baseline import BaselineDefense
from agent_security_sandbox.defenses.d1_spotlighting import SpotlightingDefense
from agent_security_sandbox.defenses.d2_policy_gate import PolicyGateDefense
from agent_security_sandbox.defenses.d3_task_alignment import TaskAlignmentDefense
from agent_security_sandbox.defenses.d4_reexecution import ReExecutionDefense
from agent_security_sandbox.defenses.registry import (
    create_composite_defense,
    create_defense,
    load_defenses_from_yaml,
)

# ---------------------------------------------------------------------------
# create_defense
# ---------------------------------------------------------------------------

class TestCreateDefense:
    def test_all_ids(self):
        expected = {
            "D0": BaselineDefense,
            "D1": SpotlightingDefense,
            "D2": PolicyGateDefense,
            "D3": TaskAlignmentDefense,
            "D4": ReExecutionDefense,
        }
        for did, cls in expected.items():
            d = create_defense(did)
            assert isinstance(d, cls)

    def test_case_insensitive(self):
        d = create_defense("d2")
        assert isinstance(d, PolicyGateDefense)

    def test_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown defense"):
            create_defense("D99")

    def test_with_config(self):
        d = create_defense("D3", config={"alignment_threshold": 0.5})
        assert isinstance(d, TaskAlignmentDefense)
        assert d.alignment_threshold == 0.5

    def test_d3_with_llm_client(self):
        mock_client = object()
        d = create_defense("D3", llm_client=mock_client)
        assert d.llm_client is mock_client

    def test_d4_with_llm_client(self):
        mock_client = object()
        d = create_defense("D4", llm_client=mock_client)
        assert d.llm_client is mock_client

    def test_d0_ignores_llm_client(self):
        """D0 doesn't accept llm_client; it should not error."""
        d = create_defense("D0", llm_client=object())
        assert isinstance(d, BaselineDefense)


# ---------------------------------------------------------------------------
# create_composite_defense
# ---------------------------------------------------------------------------

class TestCreateCompositeDefense:
    def test_basic_composite(self):
        comp = create_composite_defense(["D1", "D2"])
        assert isinstance(comp, CompositeDefense)
        assert len(comp.strategies) == 2

    def test_composite_with_configs(self):
        configs = {
            "D3": {"alignment_threshold": 0.5},
        }
        comp = create_composite_defense(["D1", "D3"], configs=configs)
        assert len(comp.strategies) == 2
        # The D3 instance should have the custom threshold
        d3 = comp.strategies[1]
        assert isinstance(d3, TaskAlignmentDefense)
        assert d3.alignment_threshold == 0.5

    def test_composite_with_llm_client(self):
        mock = object()
        comp = create_composite_defense(["D3", "D4"], llm_client=mock)
        for s in comp.strategies:
            assert s.llm_client is mock

    def test_composite_single_defense(self):
        comp = create_composite_defense(["D0"])
        assert len(comp.strategies) == 1


# ---------------------------------------------------------------------------
# load_defenses_from_yaml
# ---------------------------------------------------------------------------

class TestLoadDefensesFromYaml:
    def test_load_normal_yaml(self, tmp_path):
        yaml_content = textwrap.dedent("""\
            defenses:
              D0:
                name: "Baseline"
                enabled: true
                config: {}
              D1:
                name: "Spotlighting"
                enabled: true
                config:
                  delimiter_start: "<<START>>"
                  delimiter_end: "<<END>>"
            combinations:
              D0_D1:
                defenses: ["D0", "D1"]
        """)
        yaml_file = tmp_path / "defenses.yaml"
        yaml_file.write_text(yaml_content)

        result = load_defenses_from_yaml(str(yaml_file))
        assert "D0" in result
        assert "D1" in result
        assert "D0_D1" in result
        assert isinstance(result["D0"], BaselineDefense)
        assert isinstance(result["D0_D1"], CompositeDefense)

    def test_disabled_defense_excluded(self, tmp_path):
        yaml_content = textwrap.dedent("""\
            defenses:
              D0:
                name: "Baseline"
                enabled: true
                config: {}
              D1:
                name: "Spotlighting"
                enabled: false
                config: {}
        """)
        yaml_file = tmp_path / "defenses.yaml"
        yaml_file.write_text(yaml_content)

        result = load_defenses_from_yaml(str(yaml_file))
        assert "D0" in result
        assert "D1" not in result

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_defenses_from_yaml("/nonexistent/path.yaml")

    def test_empty_combinations(self, tmp_path):
        yaml_content = textwrap.dedent("""\
            defenses:
              D0:
                name: "Baseline"
                config: {}
        """)
        yaml_file = tmp_path / "defenses.yaml"
        yaml_file.write_text(yaml_content)

        result = load_defenses_from_yaml(str(yaml_file))
        assert "D0" in result
        assert len(result) == 1

    def test_combination_with_empty_defenses_list(self, tmp_path):
        yaml_content = textwrap.dedent("""\
            defenses:
              D0:
                name: "Baseline"
                config: {}
            combinations:
              empty_combo:
                defenses: []
        """)
        yaml_file = tmp_path / "defenses.yaml"
        yaml_file.write_text(yaml_content)

        result = load_defenses_from_yaml(str(yaml_file))
        assert "empty_combo" not in result
