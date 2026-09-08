"""Bounded parsers for fixed native-command output."""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from app.tools._validation import clean_text, parse_json_document


def text_status(output: str) -> dict[str, str]:
    return {"status": clean_text(output, maximum=16_384)}


def json_value(output: str) -> Any:
    return parse_json_document(output, max_chars=4 * 1024 * 1024)


def key_value_lines(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines()[:10_000]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized_key = re.sub(r"[^a-z0-9]+", "_", clean_text(key, maximum=128).casefold()).strip(
            "_"
        )
        if normalized_key:
            result[normalized_key] = clean_text(value, maximum=4096)
    return result


def assignment_lines(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines()[:10_000]:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        normalized_key = re.sub(r"[^a-z0-9]+", "_", clean_text(key, maximum=128).casefold()).strip(
            "_"
        )
        if normalized_key:
            result[normalized_key] = clean_text(value, maximum=4096)
    return result


def sshd_effective_config(output: str) -> dict[str, str]:
    selected = {
        "authenticationmethods",
        "kbdinteractiveauthentication",
        "passwordauthentication",
        "permitemptypasswords",
        "permitrootlogin",
        "pubkeyauthentication",
        "x11forwarding",
    }
    result: dict[str, str] = {}
    for line in output.splitlines()[:10_000]:
        key, separator, value = line.partition(" ")
        key = key.casefold()
        if separator and key in selected:
            result[key] = clean_text(value, maximum=256)
    return result


def enabled_units(output: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for line in output.splitlines()[:20_000]:
        fields = line.split()
        if not fields:
            continue
        records.append(
            {
                "name": clean_text(fields[0], maximum=512),
                "state": clean_text(fields[1], maximum=64) if len(fields) > 1 else "enabled",
            }
        )
    return records


def package_updates(output: str) -> list[dict[str, Any]]:
    updates: list[dict[str, Any]] = []
    for line in output.splitlines()[:50_000]:
        stripped = line.strip()
        if not stripped or stripped.startswith(("Listing", "Last metadata", "Obsoleting")):
            continue
        if stripped.startswith("Inst "):
            fields = stripped.split()
            updates.append(
                {
                    "package": clean_text(fields[1], maximum=512) if len(fields) > 1 else "",
                    "detail": clean_text(stripped, maximum=2048),
                    "security_related": "security" in stripped.casefold(),
                }
            )
            continue
        fields = stripped.split()
        if len(fields) >= 2 and ("." in fields[0] or "/" in fields[0]):
            updates.append(
                {
                    "package": clean_text(fields[0], maximum=512),
                    "version": clean_text(fields[1], maximum=256),
                    "security_related": "security" in stripped.casefold(),
                }
            )
    return updates


def csv_rows(output: str, *, maximum_rows: int = 20_000) -> list[dict[str, str]]:
    reader = csv.reader(io.StringIO(output))
    rows: list[dict[str, str]] = []
    for row in reader:
        if len(rows) >= maximum_rows:
            raise ValueError("CSV result row limit exceeded")
        if not row:
            continue
        # schtasks' basic CSV format exposes name, next run time, and status.
        rows.append(
            {
                "name": clean_text(row[0], maximum=1024),
                "next_run_time": clean_text(row[1], maximum=128) if len(row) > 1 else "",
                "status": clean_text(row[2], maximum=128) if len(row) > 2 else "",
            }
        )
    return rows


def registry_startup(output: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current_key = ""
    for line in output.splitlines()[:20_000]:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.upper().startswith("HKEY_"):
            current_key = clean_text(stripped, maximum=1024)
            continue
        fields = re.split(r"\s{2,}", stripped, maxsplit=2)
        if len(fields) != 3 or not fields[1].startswith("REG_"):
            continue
        raw_command = fields[2].strip()
        executable = ""
        if raw_command.startswith('"'):
            executable = raw_command[1:].split('"', 1)[0]
        else:
            executable = raw_command.split(maxsplit=1)[0] if raw_command else ""
        records.append(
            {
                "location": current_key,
                "name": clean_text(fields[0], maximum=512),
                "value_type": clean_text(fields[1], maximum=64),
                "executable": clean_text(executable, maximum=4096),
            }
        )
    return records


def registry_values(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines()[:10_000]:
        stripped = line.strip()
        if not stripped or stripped.upper().startswith("HKEY_"):
            continue
        fields = re.split(r"\s{2,}", stripped, maxsplit=2)
        if len(fields) == 3 and fields[1].startswith("REG_"):
            values[clean_text(fields[0], maximum=256)] = clean_text(fields[2], maximum=4096)
    return values


def hotfix_json(output: str) -> list[dict[str, str]]:
    value = json.loads(output)
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("hotfix response must be an object or array")
    records: list[dict[str, str]] = []
    for item in value[:50_000]:
        if not isinstance(item, dict):
            continue
        records.append(
            {
                "update_id": clean_text(item.get("HotFixID"), maximum=128),
                "installed_on": clean_text(item.get("InstalledOn"), maximum=128),
            }
        )
    return records


def launchctl_items(output: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for line in output.splitlines()[:20_000]:
        fields = line.split(maxsplit=2)
        if len(fields) != 3 or fields[0].casefold() == "pid":
            continue
        records.append(
            {
                "pid": clean_text(fields[0], maximum=32),
                "last_exit_status": clean_text(fields[1], maximum=32),
                "label": clean_text(fields[2], maximum=512),
            }
        )
    return records


def software_update_history(output: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for line in output.splitlines()[:20_000]:
        stripped = line.strip()
        if not stripped or stripped.startswith(("Display Name", "---")):
            continue
        fields = re.split(r"\s{2,}", stripped)
        if len(fields) >= 2:
            records.append(
                {
                    "name": clean_text(fields[0], maximum=512),
                    "version": clean_text(fields[1], maximum=256),
                    "installed_on": clean_text(fields[-1], maximum=128) if len(fields) > 2 else "",
                }
            )
    return records


def software_update_list(output: str) -> list[dict[str, str | bool]]:
    """Parse cached ``softwareupdate --list`` output without trusting its prose."""

    records: list[dict[str, str | bool]] = []
    current: dict[str, str | bool] | None = None
    for line in output.splitlines()[:20_000]:
        stripped = line.strip()
        label = re.match(r"^[*-]\s*Label:\s*(.+)$", stripped, flags=re.IGNORECASE)
        if label:
            if current:
                records.append(current)
            current = {"update_id": clean_text(label.group(1), maximum=512)}
            continue
        if current is None or not stripped:
            continue
        for key, value in re.findall(
            r"(Title|Version|Recommended|Action):\s*([^,]+)",
            stripped,
            flags=re.IGNORECASE,
        ):
            normalized_key = key.casefold()
            cleaned = clean_text(value, maximum=512)
            if normalized_key == "recommended":
                current[normalized_key] = cleaned.casefold() in {"yes", "true", "1"}
            else:
                current[normalized_key] = cleaned
    if current:
        records.append(current)
    for record in records:
        searchable = f"{record.get('update_id', '')} {record.get('title', '')}".casefold()
        record["security_related"] = "security" in searchable
        record["reboot_required"] = str(record.get("action", "")).casefold() == "restart"
    return records


def lsblk_encryption(output: str) -> dict[str, Any]:
    document = parse_json_document(output, max_chars=4 * 1024 * 1024)
    if not isinstance(document, dict) or not isinstance(document.get("blockdevices"), list):
        raise ValueError("lsblk response must contain a blockdevices array")
    devices: list[dict[str, Any]] = []

    def visit(
        raw: object, depth: int = 0, protected_by_encryption: bool = False
    ) -> None:
        if depth > 16 or len(devices) >= 4096:
            raise ValueError("lsblk topology exceeds the collector limit")
        if not isinstance(raw, dict):
            return
        file_system = clean_text(raw.get("fstype"), maximum=64)
        raw_mounts = raw.get("mountpoints")
        if isinstance(raw_mounts, list):
            mounts = [clean_text(item, maximum=4096) for item in raw_mounts if item]
        else:
            single_mount = clean_text(raw.get("mountpoint"), maximum=4096)
            mounts = [single_mount] if single_mount else []
        encrypted_container = file_system.casefold() in {"crypto_luks", "bitlocker"}
        protected = protected_by_encryption or encrypted_container
        devices.append(
            {
                "name": clean_text(raw.get("name"), maximum=256),
                "type": clean_text(raw.get("type"), maximum=64),
                "filesystem": file_system,
                "mountpoints": mounts,
                "encrypted_container": encrypted_container,
                "protected_by_encrypted_container": protected,
            }
        )
        children = raw.get("children", [])
        if isinstance(children, list):
            for child in children:
                visit(child, depth + 1, protected)

    for device in document["blockdevices"]:
        visit(device)
    root_volumes = [
        bool(item["protected_by_encrypted_container"])
        for item in devices
        if "/" in item["mountpoints"]
    ]
    return {
        "devices": devices,
        "encrypted_container_count": sum(item["encrypted_container"] for item in devices),
        "root_volume_encrypted": all(root_volumes) if root_volumes else None,
    }


def systemd_unit_properties(output: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    allowed = {"Id", "LoadState", "ActiveState", "UnitFileState"}
    for line in [*output.splitlines()[:10_000], ""]:
        stripped = line.strip()
        if not stripped:
            if current:
                records.append(
                    {
                        "name": current.get("Id", "unknown"),
                        "installed": str(current.get("LoadState") == "loaded").casefold(),
                        "active": str(current.get("ActiveState") == "active").casefold(),
                        "enabled": str(current.get("UnitFileState") == "enabled").casefold(),
                    }
                )
                current = {}
            continue
        key, separator, value = stripped.partition("=")
        if separator and key in allowed:
            current[key] = clean_text(value, maximum=256)
    return records


def automatic_update_units(output: str) -> dict[str, Any]:
    units = systemd_unit_properties(output)
    enabled = any(
        unit.get("enabled") == "true" or unit.get("active") == "true" for unit in units
    )
    return {"status": "enabled" if enabled else "disabled", "units": units}


def launchctl_disabled_services(output: str) -> dict[str, str | None]:
    match = re.search(r'"com\.apple\.screensharing"\s*=>\s*(true|false)', output, re.I)
    if match is None:
        return {"status": None}
    disabled = match.group(1).casefold() == "true"
    return {"status": "disabled" if disabled else "enabled"}
