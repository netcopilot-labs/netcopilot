# Contributing to NetCopilot

Thanks for your interest. NetCopilot is an open-source **Network Context Agent**
released under Apache 2.0.

## Ground rules

- **Context, never actuation.** NetCopilot reads and models networks; it never
  pushes changes to devices. Contributions must preserve this invariant.
- **Bring your own network.** No real network data, credentials, internal IPs,
  or topology belong in the repo or in tests. Use synthetic fixtures.
- **License.** By contributing you agree your contribution is licensed under
  Apache 2.0. Sign off your commits (`git commit -s`, Developer Certificate of
  Origin).

## The most useful contribution: a new vendor collector

NetCopilot is designed so the community adds vendor support **in parallel,
without touching the core**, via the collector interface. A typical vendor
contribution:

1. Implements the collector interface for the new platform.
2. Adds parsers that emit the canonical JSON shape.
3. Ships synthetic fixtures + tests (no real device data).

*(The collector interface and the canonical JSON contract are documented as the
codebase lands — see `docs/`.)*

## Project name

"NetCopilot" is the name of this project, authored and owned by Carlos Aspe.
Please don't use the name in ways that imply endorsement of forks or derivatives.
