# Skills/Specs Backlog Audit — Do Items 1 & 2 Add Value?

**Date:** 2026-07-03 · **Repo:** `/opt/dev/netcopilot-labs` @ `8bbba75` (main) · **Method:** read-only code audit
**Scope:** verify hypotheses H1–H6 from the 2026-06-30 workshop backlog
(`project_netcopilot_skills_specs_work.md`) against actual code; deliver GO/NO-GO/CONDITIONAL
verdicts for Item 1 (tools as disciplined skills), Item 2 (spec-driven rules/tools), and the
orchestrator change they imply. Zero code modified; this document is the only artifact.

All counts below are measured (commands quoted inline), not estimated. All paths are
repo-relative to `/opt/dev/netcopilot-labs`.

---

## 1. Hypothesis table

| # | Hypothesis (2026-06-30 scan) | Result | Evidence |
|---|---|---|---|
| H1 | ~21 tool modules in `src/netcopilot/mcp/tools/`; pitch says 28 | **PARTIAL** | 23 `.py` files incl. empty `__init__.py` → **22 modules**, but **25 registered tools** (`grep -cE '"name": "' src/netcopilot/mcp/registry.py` → 25; `_HANDLERS` has 25 entries, `registry.py:503-529`). `onboarding.py` exports 3 tools, `rag.py` exports 2. Neither "~21" nor "28" is the tool count: **the number is 25**. |
| H2 | Zero enforced output contracts; tools return free-form dicts | **CONFIRMED — and stronger** | `grep -rnE "pydantic\|BaseModel\|TypedDict\|@dataclass\|class .*Schema" src/netcopilot/mcp/` → 0 hits. Tools don't even return dicts: **all 25 return free-form `str`** (`-> str` on every handler; `dispatch(...) -> str`, `registry.py:532`). `TOOL_SCHEMAS` constrains inputs only. Nuance: structured shapes exist in 3 places and are destroyed or side-channeled at the tool boundary — `DiffResult.to_dict()` (`tools/run_diff.py:9-11,40-41`), `generate_report`'s `__highlight__:<json>` marker (`tools/report.py:152`), `get_redundancy_assessment`'s internal `status`/`risk` dicts flattened to prose (`tools/redundancy.py:196-210`). |
| H3 | `rule-catalog.yaml` exists; some rules have vague/gameable criteria | **CONFIRMED — with a major nuance** | Catalog at `src/netcopilot/rules/rule-catalog.yaml` (not `docs/domain/rules/`), **426 rules** (`grep -c "^- rule_id:"`). Nuance the hypothesis missed: **94 rules already carry an executable `eval` spec** validated against a closed operator set (`catalog_loader.py:74,529`) — partial spec discipline exists. Gameable examples confirmed: `CIS_FG_2_1_3` (yaml:5990) description says "properly configured (manual review)" while its `eval` (yaml:6018-6023) hardcodes `timezone equals '00'` — a live spec/impl mismatch; ~8 CIS rules are "manual review"/"NOT IMPLEMENTED" placeholders (e.g. yaml:5841, 6128, 6497); cross-device timer rules use undefined "consistent/inconsistent" (yaml:1137, 1196, 1718). |
| H4 | No SKILL.md-style discipline anywhere | **CONFIRMED** | `find . -name "SKILL.md"` → none; no `skills/` dir, no project `.claude/` dir. |
| H5 | Server uses FastMCP → item 1 is a contract layer, not a rewrite | **PARTIAL** | FastMCP is used (`server.py:14,20`) **but only 3 of 25 tools are decorated** (`grep -rn "@mcp.tool" src/` → `server.py:29,49,70`: `query_topology`, `get_findings`, `blast_radius`). The authoritative registry is the hand-rolled `TOOL_SCHEMAS` + `_HANDLERS` in `registry.py`, consumed by the in-process orchestrator, not by FastMCP. So item 1 *is* a contract layer (no rewrite needed) — but on `registry.py`/`dispatch`, not on FastMCP. **First-class finding:** external MCP clients see 3/25 tools, while `server.py:3-4` ("any MCP-compatible client can discover and call these tools") and `README.md:29-31` ("exposed over MCP so any reasoning agent can call it") describe the full surface. Doc-vs-implementation drift. |
| H6 | Orchestrator doesn't consume structured verdicts; may need changes | **CONFIRMED** | Orchestrator identified: `src/netcopilot/orchestrator.py::run_tool_loop` (:179). Tool results are raw strings appended opaquely to history (:238-239). No status/verdict branching, no retry; only name-gated side effects (§3). |

**Working-tree note:** audit ran against a clean tree at `8bbba75` (`git status` clean before the audit; after it, only this file is new). The repo is not mid-refactor; hypotheses were tested against current state.

---

## 2. Per-tool audit table — all 25 registered tools

Measured count: **25** tools (`registry.py:44-469` schema names; handlers `:503-529`).
Column semantics — **Shape:** is the output shape machine-enforced anywhere? **Failures named:** does the tool return explicit, distinct sentences for unavailable / not-found / no-data (vs raising or silently returning empty)? **Verdict:** does the result contain a judgment (health/risk/pass-fail), even in prose, vs a pure data dump? **One job:** single responsibility per the workshop bar.

| Tool | Module | Shape | Failures named | Verdict | One job | Evidence (file:line) |
|---|---|---|---|---|---|---|
| query_topology | topology.py | No (str) | Yes | No | Yes | unavailable :26; not-found + service redirect :80-89 |
| get_findings | findings.py | No (str) | Yes | No (counts) | Yes | no-data :47; **anti-inflation empty-severity distribution :74-77, 115-125** |
| blast_radius | analysis.py | No (str) | Yes | **Partial** — prose `Risk: HIGH/MODERATE/LOW` :83-84, 97 | Yes | unavailable :29; not-found :45-48 |
| explain_finding | explain.py | No (str) | Yes | No | Yes | rule-not-found + similar-rule suggestions :36-44 |
| analyze_findings | analyze.py | No (str) | Yes | No | Yes | no-data :67; all-acked :74-78; not-found + suggestions :86; fixed 3-section layout (SUMMARY/ANALYSIS/REMEDIATION) :120-215 — shape by convention only; silent catalog-load fallback :51-53 |
| get_device_detail | device.py | No (str) | Yes | No | Yes | unavailable :30; not-a-device service redirect :80-91; silent `"data unavailable"` swallows :253-254, 286-287 |
| get_shared_services | shared_services.py | No (str) | Yes | No | **No** — IP-lookup mode grafted via `ip` param :36-37 → `_lookup_ip` :198 is a second job | no-match :128, 157; invalid IP :244; ARP-miss :324 |
| get_systemic_patterns | correlation.py | No (str) | Yes | No (risk scores listed) | Yes | unavailable :28; not-found :45; engine error surfaced :50-52 |
| get_redundancy_assessment | redundancy.py | No (str) | Yes | **Yes (prose)** — per-device `status` ∈ {fully_redundant…isolated}, `risk` ∈ {low…critical} built internally :196-210, then flattened :241-374 | Yes | unavailable :24; not-found :45 |
| trace_path | path_tracer.py | No (str) | Yes — best in class | Partial — summary `Firewall: YES/NO`, SPOF list :911-942 | Yes | ambiguity → interactive prompts (multi-building :559-576, multi-VRF :614-624); not-found + suggestions :670-672; loop detect :716-719; dead-ends :790-842, 899; **silent `except Exception: return None` in helpers :82-84, 207-209** |
| get_security_posture | security.py | No (str) | Partial | Partial — overview `✓ No critical security gaps detected` :614-615, ⚠ lists :601-612 | Yes | service redirect :55-59; not-found :60; no-data :266; **silent `except…: pass` blocks skip whole FortiGate sections :435-501** |
| get_security_policies | security_policies.py | No (str) | Yes — exemplary | No | Yes | missing run_id :43; **explicit empty-vs-not-collected disambiguation** :190 ("none configured (or no genie_acl.json…)"), :224, 253 |
| get_firewall_policies | firewall.py | No (str) | Yes | No | Yes | unavailable :29; none :74; filter-miss :102; surfaces implicit deny-all :125-126, 206 |
| get_traffic_shapers | traffic_shapers.py | No (str) | Yes | No (`[!]` flags) | Yes | unavailable :41; none + filter echo :89-98 |
| get_network_neighborhood | neighborhood.py | No (str) | Yes | No | Yes | unavailable :29; not-found :51-54 |
| get_site_summary | site_summary.py | No (str) | Yes | No | Yes | unavailable :26; none :57-63 |
| get_routing_table | routing.py | No (str) | Yes | No | Yes | unavailable :26; not-found :42; no-data :57; empty-filter :84, 91 |
| get_ospf_detail | ospf.py | No (str) | Yes | No | Yes (3 modes, 1 domain) | unavailable :27; not-found :50; no-data :55; read-fail :60 |
| generate_report | report.py | No (str + JSON side-channel) | Yes | No | Yes | invalid scope :80-84; no run :87-91; missing title :106-110; error :122-124; structured payload tunneled as `__highlight__:<json>` :139-152; stale path comment `agent/orchestrator.py` :150 |
| lookup_vendor_docs | rag.py | No (str) | Yes | **Partial** — `⚠ LOW COVERAGE` semantic signal :58-77 (threshold :31) | Yes | empty query :159-160; search error :176-178; no-results + reasons :43-50 |
| lookup_network_knowledge | rag.py | No (str) | Yes | Partial (same signal) | Yes | :195-196, 202-204 |
| about_netcopilot | onboarding.py | No (str, static) | N/A (no deps) | No | Yes | verbatim package text :21-23 |
| dashboard_guide | onboarding.py | No (str, static) | N/A | No | Yes | :26-28 |
| list_capabilities | onboarding.py | No (str, derived) | N/A | No | Yes | auto-derived from `TOOL_SCHEMAS` :241-248 — cannot go stale |
| diff_runs | run_diff.py | No at tool boundary — **machine shape exists upstream** (`DiffResult.to_dict`, :9-11, 40-41; served to dashboard) | Yes — best in class | Partial — `No drift — the two runs are identical` :49 | Yes | self-correcting not-found (lists available run_ids so the model can retry) :86-97, 131, 139; N-back overflow :146-150; `ValueError` → message :166-167 |

**Aggregate:** 0/25 enforce an output shape; 22/25 name their failure modes explicitly (the 3 onboarding tools have none to name); 6/25 carry a verdict-ish judgment, always in prose; 24/25 are one-job (`get_shared_services` grafts an IP-lookup second job). The failure-mode discipline is genuinely good — what is missing is *machine readability*, not care.

---

## 3. Orchestrator assessment

### What it is

`src/netcopilot/orchestrator.py` — a single client-agnostic module. Core loop
`run_tool_loop` (:179), non-streaming wrapper `answer` (:291). Depends only on the LLM
abstraction (`llm/base.py:44-59` — `LLMProvider.run_turn` → normalized `LLMResult`) and the
registry (`TOOL_SCHEMAS` + `dispatch`, imported :37). Two providers: Anthropic-native
(`llm/claude.py`) and OpenAI-compatible covering vLLM/Ollama (`llm/ollama.py`).

Consumers (verified call sites):
1. Dashboard chat SSE — `dashboard/backend/routes/agent_chat.py:31,147`
2. Telegram bot — `telegram_bot.py:27,413`
3. CLI `ask` — `cli.py:54` (via `answer`)
4. **Standalone FastMCP server** — `mcp/server.py`: no orchestration, no LLM; the *external*
   client's LLM selects tools. Exposes only 3/25 tools (H5).

### How tool outputs flow

Tool selection is done entirely by the LLM (`provider.run_turn(system, history, tools=TOOL_SCHEMAS)`
:200; loop reacts to `result.tool_calls` :210). Execution via `dispatch` (:229), which never raises
and length-caps (`registry.py:532-543`). The result is stripped of the `__highlight__` marker (:233),
truncated (:234), optionally anonymized, and appended to history **as a raw string** (:238-239).
Providers pass it verbatim to the wire (`ollama.py:47-50`, `claude.py:42-49`).

The orchestrator performs **no structured inspection** of tool output. Everything semantic is
delegated to the LLM via the system prompt (`prompts/agent_system.txt` — verbatim rule :171,
low-coverage handling :270-278, anti-hallucination contract). The only mechanical processing is
**three name-gated side channels**, each a workaround for the missing output contract:

1. **Prose scraping** — `extract_highlight` (:108-160) drives topology-map highlighting by
   parsing line prefixes (`"Device: "`, `"Hop "`, `"Blast radius"`) out of the tool text, gated
   by a hardcoded name set (:46). A wording change in `trace_path` silently breaks map
   highlighting — no test boundary, no schema.
2. **Magic marker** — `_strip_inline_highlight` (:89-105) extracts `__highlight__:<json>` that
   `generate_report` smuggles through its return string (`report.py:152`).
3. **Verbatim short-circuit** — `_VERBATIM_ONBOARDING_TOOLS` (:176) hardcodes 3 tool names whose
   output bypasses the LLM entirely (:247-265), because small local models drop the block when
   asked to quote it (documented in the constant's comment :170-175).

Errors are pass-through: a dispatch exception becomes the string `Tool 'X' failed: …`
(`registry.py:538-540`) fed to the model as an ordinary result. The orchestrator cannot tell
ok / no-data / not-found / error apart — the model is trusted to notice and behave.

### What would have to change to consume skill/spec contracts

Contained, and net-simplifying:
- `dispatch` returns a small result envelope instead of bare `str` (e.g. `status: ok|no_data|not_found|ambiguous|error`, optional `verdict`, `text`, optional `highlight`). `registry.py` is 543 lines; the change is localized.
- `run_tool_loop` branches on `envelope.status` and reads `envelope.highlight` /
  `envelope.verbatim` — **deleting** all three name-gated hacks (:46, :89-105, :108-160, :176)
  and the marker convention in `report.py:152`.
- Model-facing serialization stays `envelope.text` initially — providers and the system prompt
  untouched; anonymizer applies to the text field (:238).
- Frontend `tool_result` SSE event (:241) can carry the structured fields for free.

### Is the change justified?

**Only bundled with Item 1's envelope — not standalone.** Standalone there is no user-facing
failure today that an orchestrator-only change fixes. Bundled, it is where the envelope pays:
it converts three brittle string conventions into one typed field read and gives the loop (and
the dashboard) the ability to distinguish failure from data for the first time.

---

## 4. Value verdicts

**Axiom check first:** neither item makes NetCopilot actuate. Item 1's verdict fields are
judgments computed deterministically over already-collected data — squarely inside
"deterministic systems produce truth" (`README.md:22-27`). No automatic NO-GO triggered.

### Item 1 — wrap MCP tools as disciplined skills: **CONDITIONAL GO**

**GO on the substance** (fixed machine-readable output shape + named failure modes + verdict
field where the tool already computes one), because it fixes documented, already-bitten
failures — this is not speculative:

1. **The false-OK / drift-trap class has already bitten this codebase**, and each bite was
   patched per-case at the text layer: the `get_findings` anti-inflation guard exists because
   the model relabelled a `high` as `critical` when zero criticals existed
   (`findings.py:74-77, 115-125`; commit `d32c622`); the verbatim short-circuit exists because
   local models drop quoted blocks (`orchestrator.py:170-176`); the LaTeX sanitizer exists
   because "a prompt rule is non-deterministic — the model ignores it" (`orchestrator.py:48-52`);
   the RAG low-coverage warning exists to stop confident citation of thin corpus
   (`rag.py:27-31`). Four independent deterministic patches on the same root cause: **the tool
   boundary carries no machine-readable semantics.** A typed envelope is the root fix
   (no-makeup-fixes rule), not a new capability.
2. **Structured data is being destroyed or smuggled today:** `redundancy.py:196-210` builds
   real `status`/`risk` verdicts and flattens them; `run_diff.py` has `DiffResult.to_dict()`
   for the dashboard but the agent surface gets prose; `report.py:152` tunnels JSON through a
   string marker; `orchestrator.py:108-160` scrapes prose back *out* of the string it was
   just flattened into. The contract layer already half-exists — on both sides of the boundary,
   informally.
3. **The MCP path has no other option:** an external agent hitting `mcp/server.py` never sees
   `agent_system.txt` — the prompt-based output contract does not travel. A fixed output shape
   is the only contract that ships with the tool over MCP (relevant before widening the 3/25
   surface, and prerequisite groundwork for Item 4/gridctl).

**NO-GO on the artifact format the backlog sketched:**
- **SKILL.md per tool: NO-GO.** 25 hand-maintained files duplicating what `TOOL_SCHEMAS`
  descriptions and `agent_system.txt` routing rules already say, in a repo with **no regen/drift
  tooling** (unlike the source repo). It would create exactly the drift the workshop warns
  about ("empty sections are where drift lives"). The enforceable version of "skill discipline"
  is the envelope + the schema, not a parallel prose file.
- **"Extend `gen_boilerplate.py`": premise invalid here** — neither `gen_boilerplate.py` nor
  `scripts/gemma/` exists in this repo (`find` → none; `scripts/` holds only
  `golden_master.py`, watcher units, README).

**Trigger condition:** implement when the next consumer needs to branch on tool outcomes —
Item 3 (change-validation verdict) needs machine-readable verdicts by definition, and widening
the MCP surface needs the traveling contract. Both are already on the backlog, so the trigger
is effectively "before either of those", not "someday".

**Risk:** 25 tools × 3 orchestrated consumers × test suite/goldens. Mitigated by the envelope
carrying `text` unchanged for the model — migration is incremental and behavior-preserving per
step.

### Item 2 — spec-driven discipline on rules/tools: **CONDITIONAL GO (narrow)**

**Key correction to the premise:** spec discipline is not absent — **94/426 rules already have
executable spec contracts** (`eval` blocks; loader validates operators against a closed set,
`catalog_loader.py:74,529`, and skips/flags everything else `:311-332`). Every entry carries 12
structured fields including `required_fields` (input shape + `healthy_value`/`threshold`) and
`check_logic`. The catalog is closer to the workshop's spec ideal than the hypothesis assumed.

**GO — on the concrete defect list this audit found**, which is documented failure, not
speculation:
- `CIS_FG_2_1_3`: vague description ("properly configured — manual review") diverging from a
  hardcoded `timezone equals '00'` eval (yaml:5990 vs 6018-6023) — a live, gameable spec/impl
  mismatch; the finding text tells operators one thing while the check tests another.
- ~8 CIS placeholders shipped as rules ("manual review", "NOT IMPLEMENTED in Cyblex" —
  yaml:5841, 6128, 6497): specs with no executable meaning and no first-class status flag.
- Cross-device "consistent/inconsistent" rules with no tolerance definition (yaml:1137, 1196,
  1718): exact-match? within-tolerance? Undefined = gameable.
- No first-class enabled/disabled field — deferral is encoded by *renaming* `eval` to
  `eval_deferred` (2 rules) or `deferred_to:` (12 rules), invisible to anything but a grep.
- Stale self-description: `catalog_loader.py:14,19,23,40` says "425 rules / 37 cross_device";
  measured: **426 / 38**. Minor, but it is spec-about-spec drift in the exact file that
  enforces specs.
- Stale paths: `engine.py:107` points to `docs/domain/rules/` (source-repo layout; actual
  default is package-local, `engine.py:85`); `report.py:150` references `agent/orchestrator.py`
  (doesn't exist here).

**GO — `constitution.md` as step 0, only as part of Item 2, not standalone.** The axiom is
already written (`README.md:22-27`) and enforced culturally; the one-page formalization is
cheap and gives OSS contributors and future spec work the standard verdicts are judged
against. It fixes no bug on its own — scope it honestly as a discipline artifact.

**NO-GO — SpecKit adoption / per-rule spec files for all 426 rules.** The 332 non-eval rules
mirror Python rule classes whose behavior is pinned by the test suite and golden findings
snapshots; a third parallel description layer with no enforcement mechanism is a drift surface,
not discipline. The KISS path already exists in-repo: **the `eval` block format *is* the spec
mechanism** — extend its coverage rule-by-rule where a rule is demonstrably gameable, rather
than adopting a new framework.

### Orchestrator change: **CONDITIONAL GO — bundled with Item 1 only**

As assessed in §3: standalone it fixes nothing user-visible; bundled with the envelope it is
where the value lands, and it *reduces* orchestrator complexity (three string-convention hacks
collapse into typed field reads). Providers, system prompt, and the model-facing text remain
untouched in the first pass.

### Items 3 & 4 (out of scope — one line each, evidence directly affects them)

- **Item 3** (change-validation verdict): the machine substrate already exists —
  `DiffResult.to_dict()` is the pre/post-snapshot diff shape (`run_diff.py:9-11`); Item 3 is
  largely "envelope + verdict rules on top of the diff engine", strengthening Item 1's case.
- **Item 4** (gridctl gateway): the idea stands — least-privilege expressed in config is a
  natural fit for the axiom. Its precondition is closing the 3/25 MCP exposure gap: today an
  allow-list would have almost nothing to gate, and `README.md:29-31` + `server.py:3-4`
  currently overstate the MCP surface. Sequence: widen the surface first (with the envelope,
  so the contract travels to external agents), then put the gateway in front.

### The plain answer

**Yes, the approach adds value — as a machine-enforced output contract at the tool→consumer
boundary and as a targeted fix list for the ~15 demonstrably vague/mismatched rule specs. It
stops adding value the moment it becomes artifact production: SKILL.md files, SpecKit
workflows, or per-rule spec documents that duplicate already-enforced (eval blocks, tests,
goldens) or already-published (TOOL_SCHEMAS, system prompt) sources without an enforcement
mechanism. Enforce shapes, don't multiply prose.**

---

## 5. Recommended implementation scope (ordered, minimal, KISS)

Only if Carlos ratifies the GOs above. Each step keeps tests green independently.

1. **`constitution.md`** (~1 page, sourced from `README.md:22-27` + the operating principles
   already in `engine.py:44-49` / `catalog_loader.py:28-34`). Step 0 of Item 2.
2. **Rule-spec defect fixes** (Item 2, narrow): fix or re-tier `CIS_FG_2_1_3`; add a
   first-class `status: active|deferred|manual_review` field to the catalog (replacing the
   `eval_deferred`/`deferred_to` renaming convention) and mark the ~8 placeholders; define
   "consistent" (exact-match vs tolerance) for the three cross-device timer rules; correct the
   stale counts in `catalog_loader.py` and stale paths in `engine.py:107` / `report.py:150`.
3. **Result envelope** (Item 1 core): one small dataclass in `registry.py`
   (`status`, optional `verdict`, `text`, optional `highlight`, optional `verbatim`);
   `dispatch` returns it; model-facing content stays `envelope.text` verbatim.
4. **Migrate the 4 tools that already compute verdicts** — `get_redundancy_assessment`,
   `blast_radius`, `diff_runs`, the two RAG tools' low-coverage flag — then the remaining
   tools mechanically (text-only envelopes). No output-text changes in this step (goldens
   stay byte-identical).
5. **Orchestrator consumes the envelope**: branch on `status`, read `highlight`/`verbatim`
   fields; delete `_VERBATIM_ONBOARDING_TOOLS`, `extract_highlight` prose scraping, and the
   `__highlight__` marker convention (update `generate_report` accordingly).
6. **Then (separate scope, enabled by 3-5):** widen `mcp/server.py` from 3 to 25 tools —
   the envelope is the contract that travels to external agents — which is the actual
   precondition for Item 4.

Explicitly **not** in scope: SKILL.md files, SpecKit, spec documents for the 332 prose-only
rules, any generator tooling (no `scripts/gemma/` exists here), anything that actuates.

---

*Audit produced by Claude Code (read-only). Evidence lines verified against working tree at
commit `8bbba75`, 2026-07-03. The only filesystem change made by this audit is this file.*

**Erratum (2026-07-03, found during s02 implementation):** the "94 rules carry an
executable `eval`" figure was a grep artifact — `grep -c '^  eval:'` matches 2 lines
inside multiline `check_logic` strings. YAML-parsed truth at `8bbba75`: **92 `eval`
keys**, and the loader's actually-loaded set is **70 rules** (after the cross-device
and superseded-by-Python filters; see `CatalogResult.stats`). The direction of H3's
verdict is unaffected; the magnitude of "pre-existing spec discipline" is slightly
smaller than stated.
