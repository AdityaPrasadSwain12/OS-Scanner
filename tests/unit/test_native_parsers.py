from __future__ import annotations

import json

import pytest

from app.collectors import parsers


def test_text_and_structured_line_parsers_normalize_bounded_keys() -> None:
    assert parsers.text_status("  enabled\r\n") == {"status": "enabled"}
    assert parsers.json_value('{"enabled":true}') == {"enabled": True}
    assert parsers.key_value_lines("Firewall Status: active\nignored\n: blank") == {
        "firewall_status": "active"
    }
    assert parsers.assignment_lines("Permit Root Login = no\nignored") == {
        "permit_root_login": "no"
    }
    assert parsers.sshd_effective_config(
        "permitrootlogin no\npasswordauthentication yes\nunknown unsafe"
    ) == {"permitrootlogin": "no", "passwordauthentication": "yes"}


def test_linux_service_and_package_parsers_handle_multiple_manager_shapes() -> None:
    assert parsers.enabled_units("sshd.service enabled\ncron.service") == [
        {"name": "sshd.service", "state": "enabled"},
        {"name": "cron.service", "state": "enabled"},
    ]
    updates = parsers.package_updates(
        "Listing... Done\n"
        "Inst openssl [1.0] (1.1 Ubuntu:security)\n"
        "kernel.x86_64 6.1 security\n"
        "package/channel 2.0 updates\n"
        "not-a-package\n"
    )
    assert [record["package"] for record in updates] == [
        "openssl",
        "kernel.x86_64",
        "package/channel",
    ]
    assert [record["security_related"] for record in updates] == [True, True, False]


def test_windows_csv_registry_and_hotfix_parsers_minimize_collected_metadata() -> None:
    assert parsers.csv_rows('"Task One","Tomorrow","Ready"\n') == [
        {"name": "Task One", "next_run_time": "Tomorrow", "status": "Ready"}
    ]
    with pytest.raises(ValueError, match="row limit"):
        parsers.csv_rows("one\ntwo\n", maximum_rows=1)

    registry = (
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
        'Updater  REG_SZ  "C:\\Program Files\\Updater.exe" --token secret\n'
        "Agent  REG_EXPAND_SZ  C:\\Agent.exe --api-key secret\n"
        "Malformed REG_SZ value\n"
    )
    startup = parsers.registry_startup(registry)
    assert startup[0]["executable"] == "C:\\Program Files\\Updater.exe"
    assert startup[1]["executable"] == "C:\\Agent.exe"
    assert "secret" not in json.dumps(startup)
    assert parsers.registry_values(registry)["Updater"].endswith("--token secret")

    assert parsers.hotfix_json('{"HotFixID":"KB1","InstalledOn":"2026-01-01"}') == [
        {"update_id": "KB1", "installed_on": "2026-01-01"}
    ]
    assert parsers.hotfix_json('[null,{"HotFixID":"KB2"}]') == [
        {"update_id": "KB2", "installed_on": ""}
    ]
    with pytest.raises(ValueError, match="object or array"):
        parsers.hotfix_json('"invalid"')


def test_macos_output_parsers_skip_headers_and_detect_screen_sharing_state() -> None:
    launchctl = parsers.launchctl_items(
        "PID Status Label\n- 0 com.example.agent\nmalformed\n"
    )
    assert launchctl == [
        {"pid": "-", "last_exit_status": "0", "label": "com.example.agent"}
    ]
    history = parsers.software_update_history(
        "Display Name  Version  Date\n"
        "---\n"
        "Safari  18.0  2026-01-01\n"
        "malformed\n"
    )
    assert history == [
        {"name": "Safari", "version": "18.0", "installed_on": "2026-01-01"}
    ]
    assert parsers.launchctl_disabled_services(
        '{ "com.apple.screensharing" => true }'
    ) == {"status": "disabled"}
    assert parsers.launchctl_disabled_services(
        '{ "com.apple.screensharing" => false }'
    ) == {"status": "enabled"}
    assert parsers.launchctl_disabled_services("{}") == {"status": None}


def test_lsblk_parser_walks_bounded_tree_and_detects_encryption() -> None:
    output = json.dumps(
        {
            "blockdevices": [
                {
                    "name": "sda",
                    "type": "disk",
                    "fstype": None,
                    "mountpoint": None,
                    "children": [
                        {
                            "name": "cryptroot",
                            "type": "crypt",
                            "fstype": "crypto_LUKS",
                            "mountpoints": ["/", None],
                        },
                        "invalid-child",
                    ],
                }
            ]
        }
    )

    result = parsers.lsblk_encryption(output)

    assert result["encrypted_container_count"] == 1
    assert result["devices"][1]["mountpoints"] == ["/"]
    with pytest.raises(ValueError, match="blockdevices"):
        parsers.lsblk_encryption("[]")

    node: dict[str, object] = {"name": "root"}
    cursor = node
    for index in range(18):
        child: dict[str, object] = {"name": str(index)}
        cursor["children"] = [child]
        cursor = child
    with pytest.raises(ValueError, match="topology"):
        parsers.lsblk_encryption(json.dumps({"blockdevices": [node]}))


def test_systemd_parsers_report_update_unit_state() -> None:
    raw = (
        "Id=apt-daily.timer\n"
        "LoadState=loaded\n"
        "ActiveState=inactive\n"
        "UnitFileState=enabled\n\n"
        "Id=dnf-automatic.timer\n"
        "LoadState=not-found\n"
        "ActiveState=inactive\n"
        "UnitFileState=disabled\n"
        "Ignored=value\n"
    )
    units = parsers.systemd_unit_properties(raw)
    assert units[0] == {
        "name": "apt-daily.timer",
        "installed": "true",
        "active": "false",
        "enabled": "true",
    }
    assert parsers.automatic_update_units(raw)["status"] == "enabled"
    assert parsers.automatic_update_units("")["status"] == "disabled"
