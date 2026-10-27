from abc import ABC, abstractmethod
from typing import Optional, Type, TypeVar
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class BaseLLMClient(ABC):
    """Abstract base class for all LLM providers (Ollama, Hosted APIs, Mock)."""

    def __init__(self, model_name: str):
        self.model_name = model_name

    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.2) -> str:
        """Generate text completion from prompt."""
        pass

    @abstractmethod
    def generate_json(
        self, prompt: str, schema_cls: Type[T], system_prompt: Optional[str] = None, temperature: float = 0.1
    ) -> T:
        """Generate structured response conforming to Pydantic schema."""
        pass
