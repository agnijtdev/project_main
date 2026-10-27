from abc import ABC
from typing import Optional
from devsecops_agent.llm.base import BaseLLMClient


class BaseAgent(ABC):
    """Base class for autonomous DevSecOps agents."""

    def __init__(self, name: str, role: str, llm_client: BaseLLMClient):
        self.name = name
        self.role = role
        self.llm = llm_client
