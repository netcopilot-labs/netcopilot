"""Parse ``show inventory`` (IOS XR) for the chassis serial (Rack 0)."""
from __future__ import annotations

import re
from pathlib import Path


def parse(filepath: str) -> dict | None:
    path = Path(filepath)
    if not path.is_file():
        return None

    content = path.read_text(encoding="utf-8")
    result: dict = {"_source": path.name, "_parse_status": "success"}

    # NAME: "Rack 0", DESCR: "..."  ... SN: <serial>
    chassis_match = re.search(r'NAME:\s*"Rack 0".*?SN:\s*(\S+)', content, re.DOTALL)
    if chassis_match:
        result["serial"] = chassis_match.group(1)
    else:
        result["serial"] = None
        result["_parse_status"] = "partial"
        result["_warnings"] = ["Could not extract chassis serial"]
    return result
