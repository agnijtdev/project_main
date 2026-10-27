import json
import logging
import re
from typing import Optional, Type, TypeVar
import httpx
from pydantic import BaseModel
from devsecops_agent.config import settings
from devsecops_agent.llm.base import BaseLLMClient
from devsecops_agent.llm.mock_client import MockLLMClient

logger = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)


class OllamaClient(BaseLLMClient):
    """Client for local open-weight code models served via Ollama."""

    def __init__(self, model_name: Optional[str] = None, base_url: Optional[str] = None):
        super().__init__(model_name or settings.OLLAMA_DEFAULT_MODEL)
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")

    def generate(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.2) -> str:
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "system": system_prompt or "",
            "stream": False,
            "options": {"temperature": temperature}
        }
        try:
            with httpx.Client(timeout=60.0) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data.get("response", "")
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            raise RuntimeError(f"Ollama error: {e}")

    def generate_json(
        self, prompt: str, schema_cls: Type[T], system_prompt: Optional[str] = None, temperature: float = 0.1
    ) -> T:
        schema_json = json.dumps(schema_cls.model_json_schema(), indent=2)
        augmented_prompt = (
            f"{prompt}\n\n"
            f"You MUST output valid JSON matching this exact schema:\n"
            f"```json\n{schema_json}\n```\n"
            f"Output ONLY the JSON object and nothing else."
        )
        raw_text = self.generate(augmented_prompt, system_prompt=system_prompt, temperature=temperature)
        return _extract_and_parse_json(raw_text, schema_cls)


class HostedLLMClient(BaseLLMClient):
    """
    Client for hosted API-based models (Gemini, OpenAI, etc.) using OpenAI-compatible endpoints.
    Used for Attacker script synthesis, Patcher root-cause analysis, and Critic code audits.
    """

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        provider: Optional[str] = None
    ):
        provider = provider or settings.LLM_PROVIDER
        if provider == "gemini" or (not api_key and settings.GEMINI_API_KEY):
            self.base_url = (base_url or "https://generativelanguage.googleapis.com/v1beta/openai").rstrip("/")
            self.api_key = api_key or settings.GEMINI_API_KEY or ""
            model = model_name or settings.GEMINI_MODEL
        else:
            self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
            self.api_key = api_key or settings.OPENAI_API_KEY or settings.HOSTED_LLM_API_KEY or ""
            model = model_name or settings.HOSTED_LLM_MODEL

        super().__init__(model)

    def generate(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.2) -> str:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature
        }

        with httpx.Client(timeout=90.0) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    def generate_json(
        self, prompt: str, schema_cls: Type[T], system_prompt: Optional[str] = None, temperature: float = 0.1
    ) -> T:
        schema_json = json.dumps(schema_cls.model_json_schema(), indent=2)
        augmented_prompt = (
            f"{prompt}\n\n"
            f"You MUST return ONLY a valid JSON object strictly adhering to this schema:\n"
            f"```json\n{schema_json}\n```\n"
            f"Do not include any other markdown formatting outside of the JSON block."
        )
        raw_text = self.generate(augmented_prompt, system_prompt=system_prompt, temperature=temperature)
        return _extract_and_parse_json(raw_text, schema_cls)


def _extract_and_parse_json(raw_text: str, schema_cls: Type[T]) -> T:
    # 1. Search for ```json ... ``` code fence
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", raw_text)
    candidate_str = match.group(1).strip() if match else raw_text.strip()
    try:
        data = json.loads(candidate_str)
        return schema_cls.model_validate(data)
    except Exception:
        pass

    # 2. Regex outermost {...}
    brace_match = re.search(r"(\{[\s\S]*\})", raw_text)
    if brace_match:
        try:
            data = json.loads(brace_match.group(1).strip())
            return schema_cls.model_validate(data)
        except Exception:
            pass

    raise ValueError(f"Could not parse valid {schema_cls.__name__} from LLM response:\n{raw_text}")


def get_llm_client(role: str = "general", escalate: bool = False) -> BaseLLMClient:
    """
    Factory for hybrid model backend:
    - If Gemini API Key or OpenAI API Key is provided, routes to real Hosted LLM.
    - If Ollama is selected, routes to local Ollama.
    - Otherwise defaults to deterministic MockLLMClient for offline evaluation.
    """
    if settings.LLM_PROVIDER == "gemini" or settings.GEMINI_API_KEY:
        logger.info(f"Using Google Gemini LLM backend ({settings.GEMINI_MODEL}) for role '{role}'.")
        return HostedLLMClient(provider="gemini")

    if settings.LLM_PROVIDER == "openai" or settings.OPENAI_API_KEY or settings.HOSTED_LLM_API_KEY:
        logger.info(f"Using OpenAI LLM backend ({settings.HOSTED_LLM_MODEL}) for role '{role}'.")
        return HostedLLMClient(provider="openai")

    if settings.LLM_PROVIDER == "ollama":
        logger.info(f"Using local Ollama LLM backend ({settings.OLLAMA_DEFAULT_MODEL}) for role '{role}'.")
        return OllamaClient()

    logger.info(f"Using MockLLMClient for role '{role}'.")
    return MockLLMClient()
