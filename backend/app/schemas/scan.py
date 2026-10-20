
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator


PACKAGE_NAME_PATTERN = re.compile(
    r"^(?:@[a-z0-9][a-z0-9._~-]*/)?"
    r"[a-z0-9][a-z0-9._~-]*$"
)


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package_name: str = Field(min_length=1, max_length=214)
    version: str | None = Field(default=None, max_length=100)

    @field_validator("package_name")
    @classmethod
    def validate_package_name(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("Package name must not contain surrounding whitespace")

        if not PACKAGE_NAME_PATTERN.fullmatch(value):
            raise ValueError(
                "Provide a valid npm package name, "
                "such as 'express' or '@types/node'"
            )

        return value

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str | None) -> str | None:
        if value is not None:
            value = value.strip()

            if not value:
                raise ValueError("Version must not be empty")

            if any(char.isspace() for char in value):
                raise ValueError("Version must not contain whitespace")

        return value
