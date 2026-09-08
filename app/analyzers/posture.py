"""Locally configured baseline analysis; no remote job can widen these allowlists."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.core import AnalysisSettings
from app.models import (
    BrowserExtension,
    Hardware,
    ListeningPort,
    OperatingSystem,
    PersistenceItem,
    SecurityPosture,
    Service,
    ServiceState,
    Software,
    User,
)


def _casefolded(values: set[str] | frozenset[str]) -> set[str]:
    return {value.casefold() for value in values}


class BaselineAnalyzer:
    """Classify inventory only when an administrator explicitly enables a baseline."""

    def __init__(self, settings: AnalysisSettings) -> None:
        self.settings = settings

    def analyze(self, inventory: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(inventory)
        security = result.get("security")
        posture = security if isinstance(security, SecurityPosture) else SecurityPosture()
        controls = dict(posture.controls)
        installed_kernel_packages = sorted(
            f"{item.name}={item.version or 'unknown'}"
            for item in result.get("software", [])
            if isinstance(item, Software)
            and (
                item.name.casefold().startswith("linux-image")
                or item.name.casefold().startswith("kernel-")
                or item.name.casefold() == "kernel"
            )
        )[:256]
        if installed_kernel_packages:
            controls["installed_kernel_packages"] = installed_kernel_packages

        users = [item for item in result.get("users", []) if isinstance(item, User)]
        administrators = [user for user in users if user.is_administrator]
        unexpected: list[str] = []
        if self.settings.enforce_administrator_allowlist:
            approved = _casefolded(self.settings.approved_administrator_accounts)
            unexpected = sorted(
                user.username for user in administrators if user.username.casefold() not in approved
            )
        controls["maximum_administrator_accounts"] = self.settings.maximum_administrator_accounts
        controls["administrator_allowlist_enforced"] = self.settings.enforce_administrator_allowlist

        operating_system = result.get("os")
        if (
            self.settings.enforce_os_support_catalog
            and isinstance(operating_system, OperatingSystem)
        ):
            release_key = f"{operating_system.family.value}:{operating_system.version}"
            operating_system = operating_system.model_copy(
                update={"supported": release_key in self.settings.supported_os_releases}
            )
            result["os"] = operating_system
            controls["os_support_catalog_enforced"] = True
            controls["os_release_key"] = release_key

        ports: list[ListeningPort] = []
        for port in result.get("listening_ports", []):
            if not isinstance(port, ListeningPort):
                continue
            suspicious = port.suspicious or (
                self.settings.enforce_port_allowlist
                and port.port not in self.settings.allowed_listening_ports
            )
            ports.append(port.model_copy(update={"suspicious": suspicious}))
        if "listening_ports" in result:
            result["listening_ports"] = ports

        approved_services = _casefolded(self.settings.approved_service_names)
        services: list[Service] = []
        for service in result.get("services", []):
            if not isinstance(service, Service):
                continue
            suspicious = service.suspicious or (
                self.settings.enforce_service_allowlist
                and service.name.casefold() not in approved_services
            )
            services.append(service.model_copy(update={"suspicious": suspicious}))
        if "services" in result:
            result["services"] = services

        required_services = _casefolded(self.settings.required_security_service_names)
        required_service_enabled: bool | None = None
        required_service_running: bool | None = None
        if required_services:
            by_name = {service.name.casefold(): service for service in services}
            selected_services = [by_name.get(name) for name in required_services]
            required_service_running = all(
                service is not None and service.state is ServiceState.RUNNING
                for service in selected_services
            )
            if any(service is None for service in selected_services):
                required_service_enabled = False
            else:
                startup_states = [
                    service.startup_type.casefold() if service.startup_type else None
                    for service in selected_services
                    if service is not None
                ]
                if any(
                    state in {"disabled", "off", "false", "masked"}
                    for state in startup_states
                ):
                    required_service_enabled = False
                elif all(state is not None for state in startup_states):
                    required_service_enabled = True
            controls["required_security_services"] = sorted(required_services)

        approved_persistence = _casefolded(self.settings.approved_persistence_names)
        persistence: list[PersistenceItem] = []
        for item in result.get("persistence", []):
            if not isinstance(item, PersistenceItem):
                continue
            suspicious = item.suspicious or (
                self.settings.enforce_persistence_allowlist
                and item.name.casefold() not in approved_persistence
            )
            persistence.append(item.model_copy(update={"suspicious": suspicious}))
        if "persistence" in result:
            result["persistence"] = persistence

        approved_extensions = _casefolded(self.settings.approved_browser_extension_ids)
        extensions: list[BrowserExtension] = []
        for extension in result.get("browser_extensions", []):
            if not isinstance(extension, BrowserExtension):
                continue
            risky = extension.risky or (
                self.settings.enforce_browser_extension_allowlist
                and extension.extension_id.casefold() not in approved_extensions
            )
            extensions.append(extension.model_copy(update={"risky": risky}))
        if "browser_extensions" in result:
            result["browser_extensions"] = extensions

        hardware = result.get("hardware")
        if isinstance(hardware, Hardware) and (
            posture.tpm_present is not None or posture.tpm_version is not None
        ):
            result["hardware"] = hardware.model_copy(
                update={
                    "tpm_present": (
                        hardware.tpm_present
                        if hardware.tpm_present is not None
                        else posture.tpm_present
                    ),
                    "tpm_version": hardware.tpm_version or posture.tpm_version,
                }
            )

        required_agents = _casefolded(self.settings.required_security_agent_names)
        installed_agents = _casefolded(set(posture.security_agent_names))
        running_agent_names = _casefolded(set(posture.security_agent_running_names))
        service_by_name = {service.name.casefold(): service for service in services}
        installed_agents.update(name for name in required_agents if name in service_by_name)
        running_agent_names.update(
            name
            for name in required_agents
            if (service := service_by_name.get(name)) is not None
            and service.state is ServiceState.RUNNING
        )
        required_agents_present = None
        required_agents_running = None
        if required_agents:
            required_agents_present = required_agents.issubset(installed_agents)
            required_agents_running = required_agents.issubset(running_agent_names)
            controls["missing_required_security_agents"] = sorted(
                required_agents - installed_agents
            )
            controls["stopped_required_security_agents"] = sorted(
                required_agents - running_agent_names
            )

        excessive_admins = len(administrators) > self.settings.maximum_administrator_accounts
        guest_states = [
            user.enabled for user in users if user.is_guest and user.enabled is not None
        ]
        guest_enabled = any(guest_states) if guest_states else posture.guest_account_enabled
        suspicious_ports = (
            any(port.suspicious for port in ports)
            if "listening_ports" in result
            else posture.suspicious_listening_port_detected
        )
        suspicious_services = (
            any(service.suspicious for service in services)
            if "services" in result
            else posture.suspicious_service_detected
        )
        scheduled_kinds = {"scheduled_task", "cron", "crontab"}
        scheduled_items = [item for item in persistence if item.kind.casefold() in scheduled_kinds]
        startup_items = [
            item for item in persistence if item.kind.casefold() not in scheduled_kinds
        ]
        suspicious_scheduled = (
            any(item.suspicious for item in scheduled_items)
            if "persistence" in result
            else posture.suspicious_scheduled_task_detected
        )
        suspicious_startup = (
            any(item.suspicious for item in startup_items)
            if "persistence" in result
            else posture.suspicious_startup_item_detected
        )
        analyzed_posture = posture.model_copy(
            update={
                "administrator_account_count": len(administrators)
                if users
                else posture.administrator_account_count,
                "excessive_administrator_accounts": excessive_admins
                if users
                else posture.excessive_administrator_accounts,
                "unexpected_administrator_accounts": unexpected
                if self.settings.enforce_administrator_allowlist
                else posture.unexpected_administrator_accounts,
                "security_agent_installed": required_agents_present
                if required_agents_present is not None
                else posture.security_agent_installed,
                "security_agent_running": required_agents_running
                if required_agents_running is not None
                else posture.security_agent_running,
                "security_service_enabled": required_service_enabled
                if required_service_enabled is not None
                else posture.security_service_enabled,
                "security_service_running": required_service_running
                if required_service_running is not None
                else posture.security_service_running,
                "guest_account_enabled": guest_enabled,
                "suspicious_listening_port_detected": suspicious_ports,
                "suspicious_service_detected": suspicious_services,
                "suspicious_scheduled_task_detected": suspicious_scheduled,
                "suspicious_startup_item_detected": suspicious_startup,
                "insecure_configuration": posture.insecure_configuration or excessive_admins,
                "controls": controls,
            }
        )
        approved_posture = self.settings.approved_security_posture
        if approved_posture:
            observed = analyzed_posture.model_dump(mode="json", exclude_none=False)
            drifted_fields = sorted(
                key
                for key, expected in approved_posture.items()
                if observed.get(key) is not None and observed.get(key) != expected
            )
            unknown_fields = sorted(
                key
                for key, expected in approved_posture.items()
                if expected is not None and observed.get(key) is None
            )
            controls = dict(analyzed_posture.controls)
            controls["configuration_baseline_enforced"] = True
            controls["configuration_drift_fields"] = drifted_fields
            controls["configuration_baseline_unknown_fields"] = unknown_fields
            analyzed_posture = analyzed_posture.model_copy(
                update={
                    "configuration_drift": (
                        True
                        if drifted_fields
                        else None
                        if unknown_fields
                        else False
                    ),
                    "controls": controls,
                }
            )
        result["security"] = analyzed_posture
        return result
