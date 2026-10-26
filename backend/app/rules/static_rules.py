from typing import Any


LIFECYCLE_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
}

SUSPICIOUS_COMMAND_PATTERNS = [
    "curl ",
    "wget ",
    "powershell ",
    "Invoke-WebRequest",
    "child_process",
]


def analyze_package_json(package_json: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Analyze package.json configuration using simple, explainable rules.

    These rules identify potentially risky patterns. They do not prove
    that a package is malicious.
    """
    findings: list[dict[str, Any]] = []

    if not isinstance(package_json, dict):
        return findings

    scripts = package_json.get("scripts", {})

    if not isinstance(scripts, dict):
        scripts = {}

    # Rule 1: Lifecycle scripts can execute commands during installation.
    for script_name in sorted(LIFECYCLE_SCRIPTS):
        script_value = scripts.get(script_name)

        if not isinstance(script_value, str) or not script_value.strip():
            continue

        findings.append(
            {
                "rule_id": "RS001",
                "title": "Installation lifecycle script detected",
                "severity": "medium",
                "description": (
                    f"The package defines a '{script_name}' lifecycle script "
                    "that may execute commands during installation."
                ),
                "evidence": {
                    "script_name": script_name,
                    "script_value": script_value,
                },
                "recommendation": (
                    "Review the script and verify that its commands are "
                    "necessary and expected."
                ),
            }
        )

        # Rule 2: Look for commands that deserve additional review.
        matched_patterns = [
            pattern
            for pattern in SUSPICIOUS_COMMAND_PATTERNS
            if pattern.lower() in script_value.lower()
        ]

        if matched_patterns:
            findings.append(
                {
                    "rule_id": "RS002",
                    "title": "Potentially risky command in lifecycle script",
                    "severity": "high",
                    "description": (
                        "An installation lifecycle script contains a command "
                        "pattern that warrants manual review. Such commands "
                        "can also have legitimate uses."
                    ),
                    "evidence": {
                        "script_name": script_name,
                        "matched_patterns": matched_patterns,
                        "script_value": script_value,
                    },
                    "recommendation": (
                        "Inspect the command, its destination, and its purpose "
                        "before trusting the package."
                    ),
                }
            )

    # Rule 3: Flag dependency specifications that point to Git repositories
    # or remote URLs because they need additional provenance review.
    dependencies = package_json.get("dependencies", {})

    if isinstance(dependencies, dict):
        for dependency_name, dependency_version in sorted(dependencies.items()):
            if not isinstance(dependency_version, str):
                continue

            normalized_version = dependency_version.strip().lower()

            if (
                normalized_version.startswith("git+")
                or normalized_version.startswith("git://")
                or normalized_version.startswith("github:")
                or normalized_version.startswith("http://")
                or normalized_version.startswith("https://")
            ):
                findings.append(
                    {
                        "rule_id": "RS003",
                        "title": "Non-registry dependency specification",
                        "severity": "low",
                        "description": (
                            f"Dependency '{dependency_name}' uses a Git or "
                            "URL-based specification instead of a conventional "
                            "registry version."
                        ),
                        "evidence": {
                            "dependency_name": dependency_name,
                            "dependency_specification": dependency_version,
                        },
                        "recommendation": (
                            "Verify the source, repository ownership, and "
                            "integrity of this dependency."
                        ),
                    }
                )

    return findings
