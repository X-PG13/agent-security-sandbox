"""External benchmark adapters for InjecAgent, AgentDojo, etc."""

from .agentdojo import AgentDojoAdapter
from .base import BenchmarkAdapter
from .injecagent import InjecAgentAdapter

__all__ = [
    "BenchmarkAdapter",
    "InjecAgentAdapter",
    "AgentDojoAdapter",
]
