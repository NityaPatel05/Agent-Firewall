"""Load scenarios: core A/B YAML, extra T-items, generated LivePI-style and Pinch-like benign."""

from __future__ import annotations

from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml

from firewall.eval.scenario import Scenario
from firewall.resources import data_path

Include = Literal["core", "extra", "livepi", "pinch"]
ALL_INCLUDES: tuple[Include, ...] = ("core", "extra", "livepi", "pinch")
_DIRS: dict[str, tuple[str, ...]] = {"core": ("attacks", "benign"), "extra": ("extra",)}


class ScenarioLoadError(ValueError):
    pass


@lru_cache(maxsize=64)
def _parse(path_str: str, mtime_ns: int) -> tuple[Scenario, ...]:
    data = yaml.safe_load(Path(path_str).read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else [data]
    try:
        return tuple(Scenario.model_validate(d) for d in items)
    except ValueError as exc:
        raise ScenarioLoadError(f"{path_str}: {exc}") from exc


def _from_dir(sub: str) -> list[Scenario]:
    root = data_path("scenarios", sub)
    out: list[Scenario] = []
    for p in sorted(root.glob("*.yaml")):
        out.extend(_parse(str(p), p.stat().st_mtime_ns))
    return out


def load_scenarios(*, kinds: Iterable[str] | None = None, suites: Iterable[str] | None = None,
                   ids: Iterable[str] | None = None, include: Iterable[Include] = ALL_INCLUDES,
                   seed: int = 0, check_twins: bool = True) -> list[Scenario]:
    """All selected scenarios, validated for unique ids and (unless disabled) resolvable twins."""
    inc = set(include)
    scenarios: list[Scenario] = []
    for name in ("core", "extra"):
        if name in inc:
            for sub in _DIRS[name]:
                scenarios.extend(_from_dir(sub))
    if "livepi" in inc:
        from firewall.eval.livepi import generate_livepi_scenarios

        scenarios.extend(generate_livepi_scenarios(seed=seed))
    if "pinch" in inc:
        from firewall.eval.pinch_gen import generate_pinch

        scenarios.extend(generate_pinch(seed=seed))
    validate(scenarios, check_twins=check_twins)
    k, s, i = (set(x) if x is not None else None for x in (kinds, suites, ids))
    return [sc for sc in scenarios
            if (k is None or sc.kind in k) and (s is None or sc.suite in s) and (i is None or sc.id in i)]


def validate(scenarios: list[Scenario], *, check_twins: bool = True) -> None:
    seen: set[str] = set()
    for sc in scenarios:
        if sc.id in seen:
            raise ScenarioLoadError(f"duplicate scenario id {sc.id}")
        seen.add(sc.id)
    for sc in scenarios if check_twins else ():
        if sc.twin is not None and sc.twin not in seen:
            raise ScenarioLoadError(f"{sc.id}: twin {sc.twin} does not exist")


def subset(scenarios: list[Scenario], prefix: str) -> list[Scenario]:
    """`A` / `B` / `LP` / `PB` / `T` by id prefix."""
    if prefix == "A":
        return [s for s in scenarios if s.id[0] == "A" and s.id[1:].isdigit()]
    if prefix == "B":
        return [s for s in scenarios if s.id[0] == "B" and s.id[1:].isdigit()]
    return [s for s in scenarios if s.id.startswith(prefix + "-") or (prefix == "T" and s.id[0] == "T")]
