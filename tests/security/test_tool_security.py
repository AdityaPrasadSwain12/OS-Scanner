from __future__ import annotations

from pathlib import Path

import pytest

from app.tools import AmassAdapter, AmassRequest, AmassScopeError, OpenScapAdapter, OsqueryAdapter
from app.tools.osv_scanner import OsvScannerAdapter, OsvScanRequest


class UnavailableRunner:
    def is_available(self, executable: str | Path) -> bool:
        return False

    def resolve(self, executable: str | Path) -> None:
        return None


def test_amass_rejects_unauthorized_and_injected_domains() -> None:
    adapter = AmassAdapter(runner=UnavailableRunner())  # type: ignore[arg-type]
    base = {
        "authorized_domains": ("example.com",),
        "authorization_id": "authorization-1",
        "authorized": True,
    }
    with pytest.raises(AmassScopeError):
        adapter.validate_input(AmassRequest(target="evil.example.net", **base))
    with pytest.raises(AmassScopeError):
        adapter.validate_input(AmassRequest(target="example.com;touch.invalid", **base))
    with pytest.raises(AmassScopeError):
        adapter.validate_input(
            AmassRequest(
                target="example.com",
                authorized_domains=("example.com",),
                authorization_id="authorization-1",
                authorized=False,
            )
        )


def test_amass_accepts_narrow_subdomain_authorization_without_expanding_scope() -> None:
    adapter = AmassAdapter(runner=UnavailableRunner())  # type: ignore[arg-type]
    request = AmassRequest(
        target="api.corp.example.com",
        authorized_domains=("corp.example.com",),
        authorization_id="authorization-2",
        authorized=True,
    )

    validated = adapter.validate_input(request)

    assert validated.authorized_domains == ("corp.example.com",)
    assert validated.scope == ("api.corp.example.com",)
    with pytest.raises(AmassScopeError):
        adapter.validate_input(
            AmassRequest(
                target="other.example.com",
                authorized_domains=("corp.example.com",),
                authorization_id="authorization-2",
                authorized=True,
            )
        )


@pytest.mark.parametrize("public_suffix", ["co.uk", "github.io", "s3.amazonaws.com"])
def test_amass_rejects_public_suffix_authorization(public_suffix: str) -> None:
    adapter = AmassAdapter(runner=UnavailableRunner())  # type: ignore[arg-type]
    with pytest.raises(AmassScopeError):
        adapter.validate_input(
            AmassRequest(
                target=public_suffix,
                authorized_domains=(public_suffix,),
                authorization_id="authorization-3",
                authorized=True,
            )
        )


def test_osquery_rejects_arbitrary_sql() -> None:
    adapter = OsqueryAdapter(runner=UnavailableRunner())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        adapter.validate_input("SELECT * FROM users;")


def test_osv_rejects_source_outside_approved_root(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    outside = tmp_path / "requirements.txt"
    outside.write_text("unsafe==1", encoding="utf-8")
    adapter = OsvScannerAdapter(
        approved_roots=(approved,), runner=UnavailableRunner()  # type: ignore[arg-type]
    )

    with pytest.raises(PermissionError):
        adapter.validate_input(OsvScanRequest(outside))


def test_openscap_rejects_entity_declarations() -> None:
    adapter = OpenScapAdapter(runner=UnavailableRunner())  # type: ignore[arg-type]
    malicious = "<!DOCTYPE x [<!ENTITY leak SYSTEM 'file:///etc/passwd'>]><x>&leak;</x>"

    with pytest.raises(ValueError, match="forbidden"):
        adapter.parse(malicious)
