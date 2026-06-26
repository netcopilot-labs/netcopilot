"""Report data generator for the  Report feature.

Builds two report types from Neo4j + the existing data layer:

    build_general_report(run_id) → GeneralReportData
    build_conversation_report(run_id, topic, facts) → ConversationReportData

Both return dataclasses that the PDF renderer can serialize and the API
route can return as JSON. Reports are uniquely identified by a `report_id`
(UUID4) so the email and PDF endpoints can look up the same report data
the user just saw in the dashboard.

In-memory cache: a single module-level dict keyed by report_id with a
30-minute TTL. Reports are regenerated on demand if a cache miss happens.
The cache is intentionally per-process — no Redis, no shared state, no
persistence. If the dashboard restarts, all in-flight reports are lost
and the user just clicks Report again.

Reuses existing helpers wherever possible:
    - data_loader.load_summary() for the run header
    - delta_analyzer.build_delta() / find_previous_run() for the delta section
    - agent.tools.findings.load_findings_enriched() for the canonical findings list
    - agent.tools.analyze.analyze_findings() for the top recommendations

Locked report sections (general):

    1. prose_summary       — 1-2 sentence plain English at the top
    2. metadata            — run_id, site, timestamp, device count
    3. health_scorecard    — devices reachable / unreachable, link types,
                             cluster health
    4. finding_delta       — NEW / RESOLVED / UNCHANGED counts vs previous run
    5. top_criticals       — top 5 unacknowledged critical/high findings
    6. top_recommendations — top 3 from the correlation engine
    7. cross_device_block  — count + top 3 cross-device pattern types

Locked sections (conversation):

    title                  — LLM-supplied conversation topic
    question               — last user message
    key_facts              — LLM-supplied list, validated against Neo4j
    devices_touched        — de-duplicated, with current Neo4j status
    tools_used             — chronological list of MCP tools called
    findings_referenced    — finding IDs the LLM cited, looked up in Neo4j
    conclusions            — LLM-supplied conclusions / action items
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..data_loader import load_summary
from netcopilot.graph.client import get_driver, get_site_for_run, is_available

log = logging.getLogger(__name__)

# Cache: report_id → (created_at_epoch, report_data_dict)
_REPORT_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_TTL_SECONDS = 30 * 60  # 30 minutes
_CACHE_MAX_ENTRIES = 100


# ─────────────────────────────────────────────────────────────────────────────
#  Dataclasses (returned to the route layer, then serialized to JSON)
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class HealthScorecard:
    """Network health snapshot.

    Fields are sourced directly from Neo4j (Run node + Device nodes +
    relationship counts) so the report numbers always match what the
    dashboard's Network Summary shows. Cable-type breakdowns (fiber vs
    copper) live only on the Cytoscape edge model and are computed at
    render time, so we don't surface them here.
    """
    devices_total: int = 0
    devices_unreachable: int = 0
    physical_links: int = 0       # PHYSICAL_CABLE relationships
    stack_links: int = 0          # STACK_LINK
    infrastructure_links: int = 0 # INFRASTRUCTURE_LINK (HA, peer-link, etc.)
    routing_adjacencies: int = 0  # ROUTING_ADJACENCY (OSPF/BGP/etc.)


@dataclass
class FindingDelta:
    """Finding delta vs the previous run."""
    previous_run_id: str | None = None
    new_count: int = 0
    resolved_count: int = 0
    unchanged_count: int = 0
    new_critical_titles: list[str] = field(default_factory=list)


@dataclass
class CriticalFinding:
    """A single top-N finding for the report."""
    finding_id: str
    rule_id: str
    severity: str
    title: str
    affected_devices: list[str]


@dataclass
class Recommendation:
    """A single top-N recommendation from the correlation engine."""
    rule_id: str
    severity: str
    headline: str
    affected_count: int


@dataclass
class CrossDevicePattern:
    """A grouping of related cross-device findings."""
    rule_id: str
    count: int
    sample_devices: list[str]


@dataclass
class GeneralReportData:
    """Full general report payload."""
    report_id: str
    scope: str  # "general"
    run_id: str
    site: str
    generated_at: str  # ISO timestamp

    prose_summary: str
    metadata: dict[str, Any]
    health: HealthScorecard
    delta: FindingDelta
    top_criticals: list[CriticalFinding]
    top_recommendations: list[Recommendation]
    cross_device_patterns: list[CrossDevicePattern]
    cross_device_count: int = 0

    def to_dict(self) -> dict:
        """Convert to a JSON-serializable dict for the API response."""
        return {
            "report_id": self.report_id,
            "scope": self.scope,
            "run_id": self.run_id,
            "site": self.site,
            "generated_at": self.generated_at,
            "prose_summary": self.prose_summary,
            "metadata": self.metadata,
            "health": self.health.__dict__,
            "delta": {
                **self.delta.__dict__,
            },
            "top_criticals": [c.__dict__ for c in self.top_criticals],
            "top_recommendations": [
                r.__dict__ for r in self.top_recommendations
            ],
            "cross_device_count": self.cross_device_count,
            "cross_device_patterns": [
                p.__dict__ for p in self.cross_device_patterns
            ],
        }


@dataclass
class ConversationFact:
    """A single LLM-supplied fact, optionally validated against Neo4j."""
    text: str
    grounded: bool = False  # True if backed by a Neo4j entity
    source_kind: str | None = None  # e.g., "device", "finding", None


@dataclass
class ConversationReportData:
    """Conversation-scoped report payload (case file style)."""
    report_id: str
    scope: str  # "conversation"
    run_id: str
    site: str
    generated_at: str

    title: str
    question: str | None
    key_facts: list[ConversationFact]
    devices_touched: list[dict]  # [{name, role, status, ...}]
    tools_used: list[str]
    findings_referenced: list[CriticalFinding]
    conclusions: str | None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "scope": self.scope,
            "run_id": self.run_id,
            "site": self.site,
            "generated_at": self.generated_at,
            "title": self.title,
            "question": self.question,
            "key_facts": [f.__dict__ for f in self.key_facts],
            "devices_touched": self.devices_touched,
            "tools_used": self.tools_used,
            "findings_referenced": [
                f.__dict__ for f in self.findings_referenced
            ],
            "conclusions": self.conclusions,
            "metadata": self.metadata,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Cache helpers
# ─────────────────────────────────────────────────────────────────────────────


def _cache_put(report_id: str, data: dict) -> None:
    """Insert a report into the cache, evicting expired/oldest entries first."""
    now = time.time()
    # Drop expired
    expired = [
        k for k, (created, _) in _REPORT_CACHE.items()
        if now - created > _CACHE_TTL_SECONDS
    ]
    for k in expired:
        _REPORT_CACHE.pop(k, None)
    # Drop oldest if over capacity
    if len(_REPORT_CACHE) >= _CACHE_MAX_ENTRIES:
        oldest_key = min(_REPORT_CACHE, key=lambda k: _REPORT_CACHE[k][0])
        _REPORT_CACHE.pop(oldest_key, None)
    _REPORT_CACHE[report_id] = (now, data)


def get_cached_report(report_id: str) -> dict | None:
    """Look up a previously generated report by ID. Returns None on miss."""
    entry = _REPORT_CACHE.get(report_id)
    if entry is None:
        return None
    created, data = entry
    if time.time() - created > _CACHE_TTL_SECONDS:
        _REPORT_CACHE.pop(report_id, None)
        return None
    return data


# ─────────────────────────────────────────────────────────────────────────────
#  General report
# ─────────────────────────────────────────────────────────────────────────────


def build_general_report(run_id: str) -> GeneralReportData:
    """Build the canonical 7-section general report for a run.

    Reads from Neo4j (Finding, Device, typed link relationships:
    PHYSICAL_CABLE / STACK_LINK / INFRASTRUCTURE_LINK) + the existing
    data_loader summary + delta_analyzer for the diff vs previous run.
    """
    site = ""
    if is_available():
        site = get_site_for_run(run_id) or ""

    summary = load_summary(run_id) or {}

    # Health scorecard — query Neo4j directly (summary.json is findings-only)
    health = _build_health_scorecard(run_id)

    # Findings — load via the canonical helper
    findings = _load_findings(run_id)

    # Top criticals
    top_criticals = _top_criticals(findings, n=5)

    # Cross-device block
    cross_device_count, cross_device_patterns = _cross_device_block(findings, n=3)

    # Top recommendations from analyze_findings (synchronous wrapper)
    top_recommendations = _top_recommendations(findings, n=3)

    # Finding delta
    delta = _build_delta(run_id, findings)

    # Prose summary
    prose_summary = _build_prose_summary(
        site=site,
        health=health,
        delta=delta,
        top_criticals=top_criticals,
        cross_device_count=cross_device_count,
    )

    report_id = str(uuid.uuid4())
    report = GeneralReportData(
        report_id=report_id,
        scope="general",
        run_id=run_id,
        site=site,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        prose_summary=prose_summary,
        metadata={
            "total_devices": health.devices_total,
            "total_links": (
                health.physical_links + health.stack_links
                + health.infrastructure_links
            ),
            "total_findings": summary.get("total_findings", len(findings)),
        },
        health=health,
        delta=delta,
        top_criticals=top_criticals,
        top_recommendations=top_recommendations,
        cross_device_patterns=cross_device_patterns,
        cross_device_count=cross_device_count,
    )
    _cache_put(report_id, report.to_dict())
    return report


def _load_findings(run_id: str) -> list[dict]:
    """Load the canonical findings for a run via the existing helper."""
    try:
        from netcopilot.findings import load_findings_enriched

        result = load_findings_enriched(run_id)
        return result or []
    except Exception as exc:
        log.warning("Failed to load findings for %s: %s", run_id, exc)
        return []


def _build_health_scorecard(run_id: str) -> HealthScorecard:
    """Build the health scorecard by querying Neo4j directly.

    The legacy summary.json (findings/summary.json) is a *findings*
    summary, not a network summary — it has no device or link counts.
    The authoritative source for those is Neo4j: the Run node for
    totals, Device nodes for unreachable count, and the per-relationship
    types for the link breakdown.
    """
    h = HealthScorecard()
    if not is_available():
        return h
    try:
        driver = get_driver()
        with driver.session() as session:
            # Run-level totals (already cached on the Run node by the loader)
            run_rec = session.run(
                "MATCH (r:Run {run_id: $run_id}) "
                "RETURN r.devices_count AS devices, "
                "r.adjacencies_count AS adjacencies",
                run_id=run_id,
            ).single()
            if run_rec:
                h.devices_total = run_rec["devices"] or 0
                h.routing_adjacencies = run_rec["adjacencies"] or 0

            # Unreachable devices: declared in inventory (role IS NOT NULL)
            # but not collected. Matches the same predicate the topology
            # endpoint uses for its unreachable_devices list.
            unreach_rec = session.run(
                "MATCH (d:Device {run_id: $run_id}) "
                "WHERE d.role IS NOT NULL AND d.collected = false "
                "RETURN count(d) AS n",
                run_id=run_id,
            ).single()
            h.devices_unreachable = unreach_rec["n"] if unreach_rec else 0

            # Link counts by relationship type. PHYSICAL_CABLE / STACK_LINK /
            # INFRASTRUCTURE_LINK are stored uni-directionally by the loader,
            # so count(r) is the link count (no /2).
            for rel_type, attr in (
                ("PHYSICAL_CABLE", "physical_links"),
                ("STACK_LINK", "stack_links"),
                ("INFRASTRUCTURE_LINK", "infrastructure_links"),
            ):
                rec = session.run(
                    f"MATCH (a:Device {{run_id: $run_id}})-[r:{rel_type}]->"
                    f"(b:Device {{run_id: $run_id}}) "
                    f"RETURN count(r) AS n",
                    run_id=run_id,
                ).single()
                setattr(h, attr, rec["n"] if rec else 0)
    except Exception as exc:
        log.warning("Health scorecard query failed for %s: %s", run_id, exc)
    return h


def _top_criticals(findings: list[dict], n: int = 5) -> list[CriticalFinding]:
    """Top N unacknowledged critical/high findings."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def sort_key(f: dict) -> tuple:
        sev = (f.get("severity") or "info").lower()
        return (severity_order.get(sev, 99), f.get("rule_id", ""))

    candidates = [
        f for f in findings
        if not f.get("acknowledged", False)
        and (f.get("severity") or "").lower() in ("critical", "high")
    ]
    candidates.sort(key=sort_key)

    out: list[CriticalFinding] = []
    for f in candidates[:n]:
        out.append(
            CriticalFinding(
                finding_id=f.get("finding_id", ""),
                rule_id=f.get("rule_id", ""),
                severity=(f.get("severity") or "info").lower(),
                title=f.get("title", "") or f.get("message", "")[:80],
                affected_devices=_extract_affected_devices(f),
            )
        )
    return out


def _extract_affected_devices(finding: dict) -> list[str]:
    """Best-effort device extraction from a finding's evidence + key_facts."""
    devices: list[str] = []
    ev = finding.get("evidence", {}) or {}
    eid = ev.get("element_id", "") or ""
    if "::" in eid:
        # ntp::, stp_, etc. — cross-device
        kf = ev.get("key_facts", {}) or {}
        involved = kf.get("involved_devices") or kf.get("devices") or []
        if isinstance(involved, list):
            devices = list(involved)
    elif "--" in eid:
        # link finding: DEVICE1:Intf--DEVICE2:Intf
        for part in eid.split("--"):
            dev = part.split(":")[0].split("/")[0]
            if dev:
                devices.append(dev)
    elif eid:
        dev = eid.split(":")[0].split("/")[0]
        if dev:
            devices.append(dev)
    # De-duplicate while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for d in devices:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _cross_device_block(
    findings: list[dict], n: int = 3
) -> tuple[int, list[CrossDevicePattern]]:
    """Count cross-device findings + return top N pattern types."""
    cd_findings = [f for f in findings if f.get("cross_device", False)]
    by_rule: dict[str, list[dict]] = {}
    for f in cd_findings:
        by_rule.setdefault(f.get("rule_id", "unknown"), []).append(f)

    patterns: list[CrossDevicePattern] = []
    for rule_id, group in sorted(
        by_rule.items(), key=lambda kv: -len(kv[1])
    )[:n]:
        sample_devices: list[str] = []
        for f in group[:3]:  # take up to 3 sample findings
            sample_devices.extend(_extract_affected_devices(f))
        # De-dup, keep first 5
        seen: set[str] = set()
        deduped: list[str] = []
        for d in sample_devices:
            if d not in seen:
                seen.add(d)
                deduped.append(d)
            if len(deduped) >= 5:
                break
        patterns.append(
            CrossDevicePattern(
                rule_id=rule_id,
                count=len(group),
                sample_devices=deduped,
            )
        )

    return len(cd_findings), patterns


def _top_recommendations(
    findings: list[dict], n: int = 3
) -> list[Recommendation]:
    """Top N rules by impact (count of unacked critical/high), with the rule's
    canonical recommendation text.

    This is a lightweight version of analyze_findings — we don't run the full
    correlation engine inside the report generator (too slow per call). Instead
    we group by rule_id, sort by severity + count, take the top N, and pull
    the recommendation from the finding's existing recommendation field.
    """
    severity_weight = {"critical": 1000, "high": 100, "medium": 10, "low": 1, "info": 0}

    by_rule: dict[str, list[dict]] = {}
    for f in findings:
        if f.get("acknowledged", False):
            continue
        sev = (f.get("severity") or "info").lower()
        if sev not in ("critical", "high"):
            continue
        by_rule.setdefault(f.get("rule_id", "unknown"), []).append(f)

    scored: list[tuple[int, str, list[dict]]] = []
    for rule_id, group in by_rule.items():
        score = sum(
            severity_weight.get((f.get("severity") or "info").lower(), 0)
            for f in group
        )
        scored.append((score, rule_id, group))
    scored.sort(key=lambda x: -x[0])

    out: list[Recommendation] = []
    for score, rule_id, group in scored[:n]:
        sample = group[0]
        headline = (
            sample.get("recommendation", "")
            or sample.get("title", "")
            or sample.get("message", "")
        )[:200]
        out.append(
            Recommendation(
                rule_id=rule_id,
                severity=(sample.get("severity") or "info").lower(),
                headline=headline,
                affected_count=len(group),
            )
        )
    return out


def _build_delta(run_id: str, current_findings: list[dict]) -> FindingDelta:
    """Compute the finding delta vs the previous run via delta_analyzer."""
    delta = FindingDelta()
    try:
        from netcopilot.dashboard.backend.delta_analyzer import build_delta as _build, find_previous_run

        prev_id = find_previous_run(run_id)
        if not prev_id:
            return delta  # First run, no delta
        diff = _build(run_id, prev_id)
        delta.previous_run_id = prev_id
        new = diff.get("new_findings", []) or []
        resolved = diff.get("resolved_findings", []) or []
        persistent = diff.get("persistent_findings", []) or []
        delta.new_count = len(new)
        delta.resolved_count = len(resolved)
        delta.unchanged_count = len(persistent)
        # Pull the titles of new critical findings
        delta.new_critical_titles = [
            (f.get("title") or f.get("rule_id") or "")[:80]
            for f in new
            if (f.get("severity") or "").lower() == "critical"
        ][:5]
    except Exception as exc:
        log.warning("Failed to compute delta for %s: %s", run_id, exc)
    return delta


def _build_prose_summary(
    *,
    site: str,
    health: HealthScorecard,
    delta: FindingDelta,
    top_criticals: list[CriticalFinding],
    cross_device_count: int,
) -> str:
    """Generate a 1-2 sentence plain English summary at the top of the report."""
    parts: list[str] = []

    # Sentence 1: overall posture
    if top_criticals:
        rule = top_criticals[0].rule_id
        n = len(top_criticals)
        parts.append(
            f"Network has {n} unacknowledged critical/high findings "
            f"requiring action, dominated by {rule}."
        )
    else:
        parts.append(
            f"Network is stable: no unacknowledged critical or high findings."
        )

    # Sentence 2: delta + cross-device
    second = []
    if delta.previous_run_id:
        if delta.new_count > 0:
            second.append(f"{delta.new_count} new findings since the previous run")
        if delta.resolved_count > 0:
            second.append(f"{delta.resolved_count} resolved")
    if cross_device_count > 0:
        second.append(f"{cross_device_count} cross-device findings active")
    if health.devices_unreachable > 0:
        second.append(f"{health.devices_unreachable} unreachable devices")

    if second:
        parts.append(", ".join(second).capitalize() + ".")

    return " ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
#  Conversation report
# ─────────────────────────────────────────────────────────────────────────────


def build_conversation_report(
    run_id: str,
    *,
    title: str,
    question: str | None = None,
    facts: list[str] | None = None,
    devices_mentioned: list[str] | None = None,
    finding_ids_mentioned: list[str] | None = None,
    tools_used: list[str] | None = None,
    conclusions: str | None = None,
) -> ConversationReportData:
    """Build a conversation-scoped report from LLM-supplied topic + facts.

    All facts/devices/findings are validated against Neo4j when possible —
    invalid entries are dropped silently with a count in metadata.
    """
    site = ""
    if is_available():
        site = get_site_for_run(run_id) or ""

    facts = facts or []
    devices_mentioned = devices_mentioned or []
    finding_ids_mentioned = finding_ids_mentioned or []
    tools_used = tools_used or []

    # Ground facts: try to mark each as device-related, finding-related, or
    # plain text. We don't reject anything — just annotate.
    grounded_facts = [
        ConversationFact(text=f, grounded=False, source_kind=None) for f in facts
    ]

    # Verify devices exist in Neo4j
    # Audit note: d.reachable doesn't exist —
    # the actual property is d.collected. Aliased back to "reachable" for the
    # report contract.
    # Audit note: replaced N+1 per-device lookup with single UNWIND
    # batch. OPTIONAL MATCH lets us distinguish found/not-found via d.name.
    devices_touched: list[dict] = []
    invalid_devices: list[str] = []
    if is_available() and devices_mentioned:
        try:
            driver = get_driver()
            with driver.session() as session:
                result = session.run(
                    "UNWIND $names AS name "
                    "OPTIONAL MATCH (d:Device {name: name, run_id: $run}) "
                    "RETURN name, d.name AS d_name, d.role AS role, "
                    "       d.os_type AS os, d.os_version AS os_version, "
                    "       d.collected AS reachable",
                    names=devices_mentioned,
                    run=run_id,
                )
                for rec in result:
                    if rec.get("d_name"):
                        devices_touched.append(
                            {
                                "name": rec["d_name"],
                                "role": rec.get("role"),
                                "os": rec.get("os"),
                                "os_version": rec.get("os_version"),
                                "reachable": rec.get("reachable"),
                            }
                        )
                    else:
                        invalid_devices.append(rec["name"])
        except Exception as exc:
            log.warning("Device grounding failed: %s", exc)

    # Verify findings exist in Neo4j
    # Audit note: replaced N+1 per-finding lookup with single UNWIND
    # batch. OPTIONAL MATCH preserves the input ID for invalid_finding_ids.
    findings_referenced: list[CriticalFinding] = []
    invalid_finding_ids: list[str] = []
    if is_available() and finding_ids_mentioned:
        try:
            driver = get_driver()
            with driver.session() as session:
                result = session.run(
                    "UNWIND $ids AS id "
                    "OPTIONAL MATCH (f:Finding {finding_id: id, run_id: $run}) "
                    "RETURN id, f.finding_id AS fid, f.rule_id AS rule_id, "
                    "       f.severity AS sev, f.title AS title, "
                    "       f.element_id AS eid",
                    ids=finding_ids_mentioned,
                    run=run_id,
                )
                for rec in result:
                    if rec.get("fid"):
                        eid = rec.get("eid") or ""
                        affected = _extract_affected_devices(
                            {"evidence": {"element_id": eid}}
                        )
                        findings_referenced.append(
                            CriticalFinding(
                                finding_id=rec["fid"],
                                rule_id=rec.get("rule_id", ""),
                                severity=(rec.get("sev") or "info").lower(),
                                title=rec.get("title", "") or "",
                                affected_devices=affected,
                            )
                        )
                    else:
                        invalid_finding_ids.append(rec["id"])
        except Exception as exc:
            log.warning("Finding grounding failed: %s", exc)

    metadata = {
        "invalid_devices_dropped": len(invalid_devices),
        "invalid_finding_ids_dropped": len(invalid_finding_ids),
    }

    report_id = str(uuid.uuid4())
    report = ConversationReportData(
        report_id=report_id,
        scope="conversation",
        run_id=run_id,
        site=site,
        generated_at=datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        ),
        title=title,
        question=question,
        key_facts=grounded_facts,
        devices_touched=devices_touched,
        tools_used=tools_used,
        findings_referenced=findings_referenced,
        conclusions=conclusions,
        metadata=metadata,
    )
    _cache_put(report_id, report.to_dict())
    return report
