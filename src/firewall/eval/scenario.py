"""Scenario model (attack / benign), YAML-authored; builds its MockWorld deterministically."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from firewall.agent.world import InjectionSpec as WorldInjection
from firewall.agent.world import MockWorld
from firewall.agent.world import WorldOverride as WorldPatch
from firewall.core.task_spec import TaskSpec
from firewall.llm.scripted import ScriptStep

_FROZEN = ConfigDict(frozen=True, extra="forbid")


class InjectionSpec(BaseModel):
    """Attacker text placed at a world `location` (MockWorld path syntax, e.g. `inbox[id=e7].body`)."""

    model_config = _FROZEN
    location: str
    text: str
    mode: Literal["append", "replace", "insert_marker"] = "append"


class WorldOverride(BaseModel):
    """`set` or `append` a value at a world path (see `firewall.agent.world.apply_path`)."""

    model_config = _FROZEN
    path: str
    op: Literal["set", "append"] = "set"
    value: Any = None


class OracleSpec(BaseModel):
    model_config = _FROZEN
    check: str
    params: dict[str, Any] = Field(default_factory=dict)
    negate: bool = False


class ExpectedOutcome(BaseModel):
    model_config = _FROZEN
    gate: Literal["stop", "allow", "review_then_allow"]
    controls: tuple[str, ...] = ()
    known_gap: str | None = None


class LivePIMeta(BaseModel):
    model_config = _FROZEN
    family: str
    goal: str
    surface: Literal["email", "group_chat", "local_docs", "repo_link", "gist"]


class Scenario(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)
    id: str
    kind: Literal["attack", "benign"]
    suite: str
    category: str
    title: str
    user_prompt: str
    world: str = "base"
    overrides: tuple[WorldOverride, ...] = ()
    injections: tuple[InjectionSpec, ...] = ()
    families: tuple[str, ...] | None = None
    script: tuple[ScriptStep, ...]
    legit_values: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    attack_oracle: OracleSpec | None = None
    utility_oracles: tuple[OracleSpec, ...] = ()
    attack_tools: tuple[str, ...] = ()
    expected: ExpectedOutcome
    twin: str | None = None
    task_spec_fixture: TaskSpec | None = None
    policy: str = "all"
    tags: tuple[str, ...] = ()
    livepi: LivePIMeta | None = None

    @model_validator(mode="after")
    def _check(self) -> Scenario:
        induced = [s for s in self.script if s.induced]
        if self.kind == "attack":
            if self.attack_oracle is None:
                raise ValueError(f"{self.id}: attack scenario needs attack_oracle")
            if not induced:
                raise ValueError(f"{self.id}: attack scenario needs at least one induced step")
            if not self.attack_tools:
                tools = tuple(dict.fromkeys(s.tool for s in induced if s.tool))
                object.__setattr__(self, "attack_tools", tools)
        else:
            if induced:
                raise ValueError(f"{self.id}: benign scenario has induced steps")
            if self.expected.gate == "stop":
                raise ValueError(f"{self.id}: benign scenario cannot expect 'stop'")
        for i, s in enumerate(self.script):
            if any(j >= i for j in s.needs):
                raise ValueError(f"{self.id}: step {i} needs a later step {s.needs}")
        return self

    def build_world(self) -> MockWorld:
        world = MockWorld.load(self.world)
        if self.overrides:
            world = world.apply_overrides([WorldPatch(path=o.path, value=o.value, mode=o.op)
                                           for o in self.overrides])
        if self.injections:
            world = world.render_injections([WorldInjection(path=i.location, text=i.text, mode=i.mode)
                                             for i in self.injections])
        return world

    def call_id(self, i: int) -> str:
        return self.script[i].call_id or f"call_{i}"

    @property
    def induced_call_ids(self) -> set[str]:
        return {self.call_id(i) for i, s in enumerate(self.script) if s.induced}
