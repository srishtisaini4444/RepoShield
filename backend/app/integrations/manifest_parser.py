import json
from typing import Any


class ManifestParseError(ValueError):
    """Raised when a package manifest cannot be parsed safely."""


def parse_package_json(content: str) -> dict[str, Any]:
    """Parse package.json content and validate its basic structure."""
    if not isinstance(content, str):
        raise ManifestParseError("Manifest content must be text.")

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ManifestParseError("Invalid package.json JSON.") from exc

    if not isinstance(data, dict):
        raise ManifestParseError("package.json must contain a JSON object.")

    for field in ("scripts", "dependencies", "devDependencies"):
        if field in data and not isinstance(data[field], dict):
            raise ManifestParseError(
                f"The '{field}' field must be a JSON object."
            )

    return data