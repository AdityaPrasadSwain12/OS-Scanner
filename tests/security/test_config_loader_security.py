from __future__ import annotations

from pathlib import Path

import pytest

from app.config_loader import ConfigurationError, load_settings_file


def _write(path: Path, value: str | bytes) -> Path:
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        path.write_text(value, encoding="utf-8")
    return path


@pytest.mark.parametrize("suffix", [".yaml", ".yml"])
def test_configuration_loader_accepts_bounded_yaml(tmp_path: Path, suffix: str) -> None:
    path = _write(
        tmp_path / f"scanner{suffix}",
        "environment: test\ndata_directory: local-data\nruntime:\n  max_concurrency: 2\n",
    )

    settings = load_settings_file(path)

    assert settings.environment == "test"
    assert settings.runtime.max_concurrency == 2
    assert settings.data_directory == Path("local-data")


def test_configuration_loader_accepts_json_with_utf8_bom(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "scanner.json",
        b'\xef\xbb\xbf{"environment":"test","log_level":"DEBUG"}',
    )

    settings = load_settings_file(path)

    assert settings.environment == "test"
    assert settings.log_level == "DEBUG"


@pytest.mark.parametrize(
    ("name", "document", "message"),
    [
        ("duplicate.json", '{"environment":"test","environment":"staging"}', "duplicate"),
        ("constant.json", '{"runtime":{"scan_timeout_seconds":NaN}}', "non-finite"),
        ("duplicate.yaml", "environment: test\nenvironment: staging\n", "duplicate"),
        ("alias.yaml", "defaults: &defaults\n  log_level: INFO\ncopy: *defaults\n", "anchors"),
        ("tag.yaml", "environment: !!str test\n", "explicit tags"),
        ("integer-key.yaml", "1: value\n", "keys must be strings"),
        ("array.yaml", "- test\n", "root must be an object"),
        ("invalid.json", "{", "not valid"),
        ("unknown.toml", "environment = 'test'\n", "must use"),
        ("invalid-setting.yaml", "environment: invalid\n", "validation failed"),
    ],
)
def test_configuration_loader_rejects_ambiguous_or_unsafe_documents(
    tmp_path: Path, name: str, document: str, message: str
) -> None:
    path = _write(tmp_path / name, document)

    with pytest.raises(ConfigurationError, match=message):
        load_settings_file(path)


def test_configuration_loader_rejects_invalid_utf8_and_size_limit(tmp_path: Path) -> None:
    invalid_utf8 = _write(tmp_path / "invalid.yaml", b"environment: \xff")
    with pytest.raises(ConfigurationError, match="not valid"):
        load_settings_file(invalid_utf8)

    oversized = _write(tmp_path / "oversized.json", b"{} ")
    with pytest.raises(ConfigurationError, match="bounded regular file"):
        load_settings_file(oversized, max_bytes=1)


def test_configuration_loader_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="bounded regular file"):
        load_settings_file(tmp_path / "missing.yaml")


def test_configuration_loader_rejects_symlink_when_supported(tmp_path: Path) -> None:
    target = _write(tmp_path / "target.yaml", "environment: test\n")
    link = tmp_path / "scanner.yaml"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable for this account")

    with pytest.raises(ConfigurationError, match="symbolic link"):
        load_settings_file(link)
