"""Run-to-run network diff ("drift").

Compares two runs of the same site and classifies every model entity and
finding as **added / removed / changed** (collectively *drift*), plus an
**info** tier for semi-volatile signals that change routinely (BGP prefix
counts, ARP/FDB/MAC tables, DHCP leases, session uptime/flap).

Public surface:
    - ``field_policy`` — stable keys per entity type + the drift/info/volatile
      field classification (the "what counts as a change" contract).
    - ``engine`` — ``load_run`` (disk → RunData) and ``compute_diff`` (pure
      RunData × RunData → DiffResult), plus ``diff_run_ids`` convenience.
"""

from netcopilot.diff.engine import (
    DiffResult,
    RunData,
    compute_diff,
    diff_run_ids,
    load_run,
    previous_run,
)

__all__ = [
    "DiffResult",
    "RunData",
    "compute_diff",
    "diff_run_ids",
    "load_run",
    "previous_run",
]
