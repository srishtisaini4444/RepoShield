import pytest

from app.integrations.manifest_parser import (
    ManifestParseError,
    parse_package_json,
)


def test_parses_valid_manifest():
    result = parse_package_json(
        '{"name": "demo", "scripts": {"postinstall": "node setup.js"}}'
    )

    assert result["name"] == "demo"
    assert result["scripts"]["postinstall"] == "node setup.js"


def test_rejects_invalid_json():
    with pytest.raises(ManifestParseError):
        parse_package_json('{"name": "demo"')


def test_rejects_non_object_json():
    with pytest.raises(ManifestParseError):
        parse_package_json('["not", "an object"]')


def test_rejects_invalid_scripts_field():
    with pytest.raises(ManifestParseError):
        parse_package_json('{"scripts": "not-an-object"}')


def test_accepts_missing_optional_fields():
    assert parse_package_json('{"name": "demo"}') == {"name": "demo"}