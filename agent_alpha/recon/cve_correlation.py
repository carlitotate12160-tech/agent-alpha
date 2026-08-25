"""Offline §12.67-S2 service-version to known-CVE advisory correlation."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import AttackNode, NodeType, ServiceProperties
from agent_alpha.recon.service_fingerprint import is_cve_correlation_eligible
from agent_alpha.tools.contracts import ResourceBudget, TargetContext, ToolResult
from agent_alpha.tools.registry import ToolRegistry

_CORPUS_DIR = Path(__file__).resolve().parents[2] / "data" / "cve_corpus"
_NUMERIC_VERSION = re.compile(r"^\D*(\d+(?:\.\d+)*)")


@dataclass(frozen=True)
class CveCorpusRecord:
    corpus_version: str
    product: str
    version_range: Mapping[str, str] | str
    cve_id: str
    cvss: float
    cwe: str
    kev: bool
    epss: float
    summary: str
    confirm_probe: Mapping[str, object] | None

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> CveCorpusRecord:
        version_range = value["version_range"]
        if not isinstance(version_range, (str, Mapping)):
            raise ValueError("version_range must be a max-version string or mapping")
        confirm_probe = value.get("confirm_probe")
        if confirm_probe is not None and not isinstance(confirm_probe, Mapping):
            raise ValueError("confirm_probe must be a mapping or null")
        return cls(
            corpus_version=str(value["corpus_version"]),
            product=str(value["product"]),
            version_range=version_range,
            cve_id=str(value["cve_id"]),
            cvss=float(str(value["cvss"])),
            cwe=str(value["cwe"]),
            kev=bool(value["kev"]),
            epss=float(str(value["epss"])),
            summary=str(value["summary"]),
            confirm_probe=confirm_probe,
        )


@dataclass(frozen=True)
class CveHypothesis:
    product: str
    version: str
    cve_id: str
    cvss: float
    cwe: str
    kev: bool
    epss: float
    summary: str
    corpus_version: str
    confirm_probe: Mapping[str, object] | None


def _version_tuple(value: str) -> tuple[int, ...] | None:
    match = _NUMERIC_VERSION.match(value.strip())
    if match is None:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _compare_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    left_padded = left + (0,) * (width - len(left))
    right_padded = right + (0,) * (width - len(right))
    return (left_padded > right_padded) - (left_padded < right_padded)


def _version_matches(version: str, affected: Mapping[str, str] | str) -> bool:
    parsed = _version_tuple(version)
    if parsed is None:
        return False
    if isinstance(affected, str):
        maximum = _version_tuple(affected)
        return maximum is not None and _compare_versions(parsed, maximum) <= 0

    minimum = _version_tuple(str(affected.get("min_affected", "")))
    maximum = _version_tuple(str(affected.get("max_affected", "")))
    if minimum is not None and _compare_versions(parsed, minimum) < 0:
        return False
    if maximum is not None and _compare_versions(parsed, maximum) > 0:
        return False
    return minimum is not None or maximum is not None


def _coerce_record(value: CveCorpusRecord | Mapping[str, object]) -> CveCorpusRecord:
    return value if isinstance(value, CveCorpusRecord) else CveCorpusRecord.from_mapping(value)


@lru_cache(maxsize=1)
def _default_corpus() -> tuple[CveCorpusRecord, ...]:
    return _load_paths(tuple(sorted(_CORPUS_DIR.glob("*.jsonl"))))


def _load_paths(paths: Sequence[Path]) -> tuple[CveCorpusRecord, ...]:
    records: list[CveCorpusRecord] = []
    for path in paths:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: corpus record must be an object")
            record = CveCorpusRecord.from_mapping(value)
            if record.corpus_version != constants.CVE_CORPUS_VERSION:
                raise ValueError(
                    f"{path}:{line_number}: corpus_version={record.corpus_version!r} does not "
                    f"match CVE_CORPUS_VERSION={constants.CVE_CORPUS_VERSION!r}"
                )
            records.append(record)
    return tuple(records)


def load_corpus(paths: Sequence[Path] | None = None) -> tuple[CveCorpusRecord, ...]:
    """Load the pinned human-diffable JSONL corpus without network access."""
    return _default_corpus() if paths is None else _load_paths(paths)


def correlate(
    product: str,
    version: str,
    *,
    corpus: Iterable[CveCorpusRecord | Mapping[str, object]],
) -> list[CveHypothesis]:
    """Return known-CVE hypotheses for an exact product and affected numeric version."""
    if not version:
        return []

    hypotheses = []
    normalized_product = product.casefold()
    for raw_record in corpus:
        record = _coerce_record(raw_record)
        if record.product.casefold() != normalized_product:
            continue
        if not _version_matches(version, record.version_range):
            continue
        hypotheses.append(
            CveHypothesis(
                product=product,
                version=version,
                cve_id=record.cve_id,
                cvss=record.cvss,
                cwe=record.cwe,
                kev=record.kev,
                epss=record.epss,
                summary=record.summary,
                corpus_version=record.corpus_version,
                confirm_probe=record.confirm_probe,
            )
        )
    return sorted(
        hypotheses, key=lambda hypothesis: (hypothesis.kev, hypothesis.epss), reverse=True
    )


class CveCorrelationTool:
    name = "cve_correlation"
    phase = "recon"
    required_auth = "RECON_ONLY"
    mitre_technique = "T1592.002"

    def __init__(
        self,
        service: ServiceProperties,
        corpus: Iterable[CveCorpusRecord | Mapping[str, object]],
        event_store: Any,
    ) -> None:
        self.service = service
        self._corpus = tuple(corpus)
        self._event_store = event_store

    def applies_to(self, ctx: TargetContext) -> float:
        del ctx
        return self.service.confidence if is_cve_correlation_eligible(self.service) else 0.0

    def run(self, ctx: TargetContext, budget: ResourceBudget) -> ToolResult:
        del budget
        if not self.service.version:
            self._emit_concealed(ctx)
            return ToolResult(
                tool=self.name,
                success=False,
                confidence=0.0,
                error="version CONCEALED, CVE correlation not run",
            )
        if not is_cve_correlation_eligible(self.service):
            return ToolResult(
                tool=self.name,
                success=False,
                confidence=0.0,
                error="service is not CVE-correlation eligible",
            )

        emitted = self._emit_hypotheses(
            ctx,
            correlate(self.service.name, self.service.version, corpus=self._corpus),
        )
        return ToolResult(
            tool=self.name,
            success=False,
            confidence=self.service.confidence,
            error=f"advisory_only:{emitted}",
        )

    def _emit_concealed(self, ctx: TargetContext) -> None:
        key = (ctx.target, self.service.port, self.service.name)
        if key in {
            (
                event.payload.get("host"),
                event.payload.get("port"),
                event.payload.get("product"),
            )
            for event in self._event_store.get_events(ctx.engagement_id)
            if event.event_type == EventType.RECON_TECHNIQUE_ATTEMPTED
            and event.payload.get("outcome") == "concealed"
        }:
            return
        self._event_store.append(
            EventType.RECON_TECHNIQUE_ATTEMPTED,
            ctx.engagement_id,
            "alpha",
            {
                "host": ctx.target,
                "technique_id": self.name,
                "product": self.service.name,
                "port": self.service.port,
                "outcome": "concealed",
                "negative_evidence": "version CONCEALED, CVE correlation not run",
            },
        )

    def _emit_hypotheses(
        self,
        ctx: TargetContext,
        hypotheses: Sequence[CveHypothesis],
    ) -> int:
        existing = {
            (
                event.payload.get("host"),
                event.payload.get("port"),
                event.payload.get("product"),
                event.payload.get("version"),
                event.payload.get("cve_id"),
            )
            for event in self._event_store.get_events(ctx.engagement_id)
            if event.event_type == EventType.CVE_HYPOTHESIS_RAISED
        }
        emitted = 0
        for hypothesis in hypotheses:
            key = (
                ctx.target,
                self.service.port,
                hypothesis.product,
                hypothesis.version,
                hypothesis.cve_id,
            )
            if key in existing:
                continue
            self._event_store.append(
                EventType.CVE_HYPOTHESIS_RAISED,
                ctx.engagement_id,
                "alpha",
                {
                    "host": ctx.target,
                    "port": self.service.port,
                    "product": hypothesis.product,
                    "version": hypothesis.version,
                    "cve_id": hypothesis.cve_id,
                    "cvss": hypothesis.cvss,
                    "kev": hypothesis.kev,
                    "epss": hypothesis.epss,
                    "corpus_version": hypothesis.corpus_version,
                    "tier": "self_verified",
                },
            )
            existing.add(key)
            emitted += 1
        return emitted


def dispatch_cve_correlation(
    service_nodes: Sequence[AttackNode],
    *,
    host: str,
    engagement_id: str,
    event_store: Any,
    corpus: Iterable[CveCorpusRecord | Mapping[str, object]] | None = None,
) -> int:
    """Rank and run offline recon tools over canonical SERVICE nodes, emitting advisories only."""
    records = tuple(corpus) if corpus is not None else load_corpus()
    tools = [
        CveCorrelationTool(node.properties, records, event_store)
        for node in service_nodes
        if node.type is NodeType.SERVICE and isinstance(node.properties, ServiceProperties)
    ]
    ctx = TargetContext(
        engagement_id=engagement_id,
        tenant_id=None,
        target=host,
        tech_stack={tool.service.name: tool.service.version for tool in tools},
        open_ports=tuple(sorted({tool.service.port for tool in tools})),
    )
    budget = ResourceBudget(max_requests=0, max_seconds=0.0, max_cost_usd=0.0)
    before = sum(
        1
        for event in event_store.get_events(engagement_id)
        if event.event_type == EventType.CVE_HYPOTHESIS_RAISED
    )
    recon_tools = [tool for tool in tools if tool.phase == "recon"]
    for tool in ToolRegistry(recon_tools).ranked(ctx):
        tool.run(ctx, budget)
    after = sum(
        1
        for event in event_store.get_events(engagement_id)
        if event.event_type == EventType.CVE_HYPOTHESIS_RAISED
    )
    return after - before
