
from urllib.parse import quote

import httpx


NPM_REGISTRY_URL = "https://registry.npmjs.org"


class NpmPackageNotFound(Exception):
    """Raised when the requested package does not exist in the registry."""


class NpmRegistryError(Exception):
    """Raised when the registry request fails or returns invalid data."""


class NpmRegistryClient:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def _get_json(self, url: str) -> dict:
        """Fetch JSON from the fixed npm registry and validate the response."""
        try:
            response = httpx.get(
                url,
                timeout=self.timeout,
                follow_redirects=False,
                headers={"Accept": "application/json"},
            )
        except httpx.TimeoutException as exc:
            raise NpmRegistryError(
                "The npm Registry request timed out."
            ) from exc
        except httpx.RequestError as exc:
            raise NpmRegistryError(
                "Could not connect to the npm Registry."
            ) from exc

        if response.status_code == 404:
            raise NpmPackageNotFound(
                "The requested package or version was not found on npm."
            )

        if response.status_code != 200:
            raise NpmRegistryError(
                f"The npm Registry returned HTTP {response.status_code}."
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise NpmRegistryError(
                "The npm Registry returned invalid JSON."
            ) from exc

        if not isinstance(data, dict):
            raise NpmRegistryError(
                "The npm Registry returned an unexpected response format."
            )

        return data

    def get_package_metadata(self, package_name: str) -> dict:
        """Retrieve basic metadata and the latest version of an npm package."""
        encoded_name = quote(package_name, safe="@")
        url = f"{NPM_REGISTRY_URL}/{encoded_name}"

        data = self._get_json(url)

        package_info = data.get("dist-tags")
        if not isinstance(package_info, dict):
            raise NpmRegistryError(
                "The registry response is missing valid dist-tags."
            )

        latest_version = package_info.get("latest")
        if not isinstance(latest_version, str) or not latest_version:
            raise NpmRegistryError(
                "The registry response is missing a valid latest version."
            )

        name = data.get("name")
        if (
            not isinstance(name, str)
            or name.lower() != package_name.lower()
        ):
            raise NpmRegistryError(
                "The registry response package name did not match the request."
            )

        description = data.get("description")
        if not isinstance(description, str):
            description = ""

        return {
            "name": name,
            "latest_version": latest_version,
            "description": description,
        }

    def get_package_version_metadata(
        self,
        package_name: str,
        version: str,
    ) -> dict:
        """Retrieve metadata for an exact npm package version."""
        encoded_name = quote(package_name, safe="@")
        encoded_version = quote(version, safe="")
        url = f"{NPM_REGISTRY_URL}/{encoded_name}/{encoded_version}"

        data = self._get_json(url)

        returned_name = data.get("name")
        returned_version = data.get("version")

        if (
            not isinstance(returned_name, str)
            or returned_name.lower() != package_name.lower()
        ):
            raise NpmRegistryError(
                "The registry response package name did not match the request."
            )

        if returned_version != version:
            raise NpmRegistryError(
                "The registry response version did not match the request."
            )

        description = data.get("description")
        if not isinstance(description, str):
            description = ""

        return {
            "name": returned_name,
            "version": returned_version,
            "description": description,
        }

    def get_package_manifest(
        self,
        package_name: str,
        version: str,
    ) -> dict:
        """
        Retrieve package configuration fields for an exact npm version.

        Only returns fields needed by the static rule engine.
        """
        encoded_name = quote(package_name, safe="@")
        encoded_version = quote(version, safe="")
        url = f"{NPM_REGISTRY_URL}/{encoded_name}/{encoded_version}"

        data = self._get_json(url)

        returned_name = data.get("name")
        returned_version = data.get("version")

        if (
            not isinstance(returned_name, str)
            or returned_name.lower() != package_name.lower()
        ):
            raise NpmRegistryError(
                "The registry response package name did not match the request."
            )

        if returned_version != version:
            raise NpmRegistryError(
                "The registry response version did not match the request."
            )

        scripts = data.get("scripts", {})
        dependencies = data.get("dependencies", {})
        dev_dependencies = data.get("devDependencies", {})

        if not isinstance(scripts, dict):
            scripts = {}

        if not isinstance(dependencies, dict):
            dependencies = {}

        if not isinstance(dev_dependencies, dict):
            dev_dependencies = {}

        return {
            "name": returned_name,
            "version": returned_version,
            "scripts": scripts,
            "dependencies": dependencies,
            "devDependencies": dev_dependencies,
        }
