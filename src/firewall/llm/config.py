"""Model roles and limits (`data/models.yaml`, env override `FIREWALL_MODEL_<ROLE>=provider:model`)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict

from firewall.resources import data_path

Provider = Literal["google", "groq", "scripted"]


class ModelSpec(BaseModel):
    model_config = ConfigDict(frozen=True)
    provider: Provider
    model: str
    thinking: Literal["minimal", "low", "medium", "high"] | None = None
    temperature: float = 0.0


class ModelLimits(BaseModel):
    model_config = ConfigDict(frozen=True)
    rpm: int
    tpm: int
    rpd: int
    price_in: float = 0.0     # USD per 1M input tokens
    price_out: float = 0.0    # USD per 1M output tokens
    rpd_reset_tz: str = "UTC"


class ModelConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    roles: dict[str, ModelSpec]
    limits: dict[str, ModelLimits]
    default_limits: ModelLimits

    def role(self, name: str) -> ModelSpec:
        try:
            return self.roles[name]
        except KeyError as exc:
            raise KeyError(f"unknown model role {name!r}") from exc

    def limits_for(self, model: str) -> ModelLimits:
        return self.limits.get(model, self.default_limits)


def load_model_config(path: Path | None = None) -> ModelConfig:
    data = yaml.safe_load((path or data_path("data", "models.yaml")).read_text(encoding="utf-8"))
    cfg = ModelConfig.model_validate(data)
    roles = dict(cfg.roles)
    for key, value in os.environ.items():
        if key.startswith("FIREWALL_MODEL_") and ":" in value:
            role = key.removeprefix("FIREWALL_MODEL_").lower()
            provider, model = value.split(":", 1)
            base = roles.get(role)
            roles[role] = ModelSpec(provider=provider, model=model,  # type: ignore[arg-type]
                                    thinking=base.thinking if base else None,
                                    temperature=base.temperature if base else 0.0)
    return cfg.model_copy(update={"roles": roles})
