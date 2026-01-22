"""
Unit tests for SBOM parser helpers and the SBOMParser class.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbom_compile_order.parser import (
    SBOMParser,
    build_maven_central_url,
    build_maven_central_url_from_purl,
    clean_artifact_name,
    extract_package_type,
    parse_purl,
)


def test_clean_artifact_name_strips_version_and_extension() -> None:
    assert clean_artifact_name("flogger-0.7.1.jar", "0.7.1") == "flogger"


def test_clean_artifact_name_falls_back_when_no_version_match() -> None:
    assert clean_artifact_name("flogger-0.7.1-extra") == "flogger-0.7.1-extra"


def test_parse_purl_extracts_maven_coordinates() -> None:
    group, artifact, version, file_type = parse_purl(
        "pkg:maven/org.example/flogger@0.7.1?type=pom"
    )
    assert group == "org.example"
    assert artifact == "flogger"
    assert version == "0.7.1"
    assert file_type == "pom"


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("", (None, None, None, None)),
        ("pkg:npm/@scope/package", (None, None, None, None)),
    ],
)
def test_parse_purl_returns_none_for_invalid(purl: str, expected: tuple) -> None:
    assert parse_purl(purl) == expected


def test_extract_package_type_parses_pkg_scheme() -> None:
    assert extract_package_type("pkg:maven/org.example/flogger@0.7.1") == "maven"
    assert extract_package_type("invalid-purl") is None


def test_build_maven_central_url_constructs_expected_path() -> None:
    url = build_maven_central_url(
        "org.example", "flogger", "0.7.1", file_type="jar", base_url="https://repo1.maven.org/maven2"
    )
    assert url.endswith("/org/example/flogger/0.7.1/flogger-0.7.1.jar")


def test_build_maven_central_url_supports_war_type() -> None:
    url = build_maven_central_url(
        "org.example", "service", "1.2.3", file_type="war", base_url="https://repo1.maven.org/maven2"
    )
    assert url.endswith("/org/example/service/1.2.3/service-1.2.3.war")


def test_build_maven_central_url_from_purl_uses_type_override() -> None:
    url = build_maven_central_url_from_purl(
        "pkg:maven/org.example/flogger@0.7.1?type=pom"
    )
    assert url.endswith("/org/example/flogger/0.7.1/flogger-0.7.1.pom")


def _write_sbom(tmp_path: Path, payload: dict) -> Path:
    sbom_path = tmp_path / "test.sbom.json"
    sbom_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return sbom_path


def test_sbom_parser_reads_components_and_dependencies(tmp_path: Path) -> None:
    sbom_payload = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "bom-ref": "pkg:maven/org.example/base@0.5.0",
                "group": "org.example",
                "name": "base",
                "version": "0.5.0",
            },
            {
                "bom-ref": "pkg:maven/org.example/utils@2.0.0",
                "group": "org.example",
                "name": "utils",
                "version": "2.0.0",
            },
        ],
        "dependencies": [
            {
                "ref": "pkg:maven/org.example/utils@2.0.0",
                "dependsOn": ["pkg:maven/org.example/base@0.5.0"],
            }
        ],
    }
    sbom_path = _write_sbom(tmp_path, sbom_payload)

    parser = SBOMParser(sbom_path)
    parser.parse()

    components = parser.get_all_components()
    assert len(components) == 2
    assert parser.get_component_by_ref("pkg:maven/org.example/base@0.5.0") is not None

    dependencies = parser.get_dependencies()
    assert dependencies["pkg:maven/org.example/utils@2.0.0"] == [
        "pkg:maven/org.example/base@0.5.0"
    ]


def test_sbom_parser_fails_on_invalid_format(tmp_path: Path) -> None:
    sbom_path = _write_sbom(tmp_path, {"bomFormat": "NotCycloneDX"})
    parser = SBOMParser(sbom_path)
    with pytest.raises(ValueError):
        parser.parse()


def test_sbom_parser_requires_file_exists(tmp_path: Path) -> None:
    parser = SBOMParser(tmp_path / "missing.json")
    with pytest.raises(FileNotFoundError):
        parser.parse()
