"""Deterministically merge independent collector contributions."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel

from app.models import (
    GPU,
    BrowserExtension,
    CertificateInfo,
    Disk,
    IPAddress,
    ListeningPort,
    NetworkInterface,
    PersistenceItem,
    Process,
    Service,
    Software,
    UpdateInfo,
    User,
)


def _identity(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", exclude_none=True)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _folded(value: object | None) -> str | None:
    if value is None:
        return None
    return str(value).strip().casefold()


def _list_identity(value: Any) -> str:
    """Return a source-independent identity for scanner-owned inventory rows."""

    identity: tuple[object, ...] | None = None
    if isinstance(value, Software):
        # Vendor, manager, path, and source describe the observation rather
        # than the installed artifact. Version and architecture remain in the
        # key so parallel releases/installations are never collapsed.
        identity = (
            "Software",
            _folded(value.name),
            value.version.strip() if value.version is not None else None,
            _folded(value.architecture),
        )
    elif isinstance(value, Process):
        # A PID is unique for the duration of this single endpoint snapshot.
        identity = ("Process", value.pid)
    elif isinstance(value, Service):
        identity = ("Service", _folded(value.name))
    elif isinstance(value, User):
        identity = ("User", value.uid or _folded(value.username))
    elif isinstance(value, NetworkInterface):
        identity = ("NetworkInterface", _folded(value.name))
    elif isinstance(value, ListeningPort):
        # PID/process metadata may be absent from one source. The bound socket
        # tuple is the endpoint identity and keeps distinct addresses and
        # protocols separate.
        identity = (
            "ListeningPort",
            value.protocol.value,
            value.address,
            value.port,
        )
    elif isinstance(value, PersistenceItem):
        identity = (
            "PersistenceItem",
            _folded(value.kind),
            _folded(value.name),
            _folded(value.user),
        )
    elif isinstance(value, BrowserExtension):
        identity = (
            "BrowserExtension",
            _folded(value.browser),
            value.extension_id.strip(),
        )
    elif isinstance(value, CertificateInfo):
        identity = (
            "CertificateInfo",
            _folded(value.store),
            _folded(value.thumbprint or value.serial_number or value.subject),
        )
    elif isinstance(value, UpdateInfo):
        identity = (
            "UpdateInfo",
            _folded(value.update_id),
            value.version.strip() if value.version is not None else None,
            value.installed,
        )
    elif isinstance(value, Disk):
        identity = (
            "Disk",
            _folded(value.name),
            value.mount_point,
        )
    elif isinstance(value, GPU):
        identity = ("GPU", _folded(value.model), value.memory_bytes)
    elif isinstance(value, IPAddress):
        identity = ("IPAddress", value.address)
    if identity is not None:
        return _identity(identity)
    return _identity(value)


def _merge_model(current: BaseModel, incoming: BaseModel) -> BaseModel:
    # Preserve nested model instances while merging. ``model_dump`` flattens
    # them into dictionaries, which would discard the stable identities above
    # for disks, GPUs, and interface addresses.
    field_names = type(current).model_fields
    combined = merge_inventory(
        {name: getattr(current, name) for name in field_names},
        {name: getattr(incoming, name) for name in field_names},
    )
    return type(current).model_validate(combined)


def merge_inventory(base: Mapping[str, Any], patch: Mapping[str, Any]) -> dict[str, Any]:
    """Merge model/dict inventory, preferring concrete native posture over unknowns."""

    merged = dict(base)
    for key, incoming in patch.items():
        if incoming is None:
            continue
        current = merged.get(key)
        if isinstance(current, Mapping) and isinstance(incoming, Mapping):
            merged[key] = merge_inventory(current, incoming)
        elif (
            isinstance(current, BaseModel)
            and isinstance(incoming, BaseModel)
            and type(current) is type(incoming)
        ):
            merged[key] = _merge_model(current, incoming)
        elif isinstance(current, list) and isinstance(incoming, list):
            result = list(current)
            positions = {_list_identity(item): index for index, item in enumerate(result)}
            for item in incoming:
                identity = _list_identity(item)
                position = positions.get(identity)
                if position is None:
                    positions[identity] = len(result)
                    result.append(item)
                elif (
                    isinstance(result[position], BaseModel)
                    and isinstance(item, BaseModel)
                    and type(result[position]) is type(item)
                ):
                    result[position] = _merge_model(result[position], item)
            merged[key] = result
        else:
            merged[key] = incoming
    return merged
