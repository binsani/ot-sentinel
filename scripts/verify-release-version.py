"""Verify that every OT-Sentinel release surface uses the same semantic version."""

import argparse
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--tag")
    return parser.parse_args()


def project_version(path: Path) -> str:
    with path.open("rb") as source:
        return str(tomllib.load(source)["project"]["version"])


def locked_project_version(path: Path, project_name: str) -> str:
    with path.open("rb") as source:
        packages = tomllib.load(source)["package"]
    package = next(item for item in packages if item["name"] == project_name)
    return str(package["version"])


def verify(expected: str, tag: str | None = None) -> list[str]:
    if not SEMVER.fullmatch(expected):
        return [f"expected version is not stable semantic version: {expected}"]
    versions = {
        "backend project": project_version(ROOT / "backend" / "pyproject.toml"),
        "backend lock": locked_project_version(
            ROOT / "backend" / "uv.lock", "ot-sentinel-backend"
        ),
        "sensor project": project_version(ROOT / "sensor" / "pyproject.toml"),
        "sensor lock": locked_project_version(
            ROOT / "sensor" / "uv.lock", "ot-sentinel-sensor"
        ),
        "frontend project": str(
            json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))["version"]
        ),
    }
    frontend_lock = json.loads(
        (ROOT / "frontend" / "package-lock.json").read_text(encoding="utf-8")
    )
    versions["frontend lock"] = str(frontend_lock["version"])
    versions["frontend root package lock"] = str(frontend_lock["packages"][""]["version"])
    violations = [
        f"{name} is {version}, expected {expected}"
        for name, version in versions.items()
        if version != expected
    ]
    required_text = {
        ROOT / "backend" / "app" / "main.py": f'version="{expected}"',
        ROOT / "backend" / "app" / "exports.py": f'"version": "{expected}"',
        ROOT / "README.md": f"Version {expected}",
        ROOT / "CHANGELOG.md": f"## {expected} -",
    }
    for path, snippet in required_text.items():
        if snippet not in path.read_text(encoding="utf-8"):
            violations.append(f"{path}: missing version marker {snippet}")
    deployment_files = tuple((ROOT / "deploy" / "kubernetes" / "base").glob("*.yaml"))
    old_image = re.compile(r"ghcr\.io/binsani/ot-sentinel-(?:backend|frontend):v(\d+\.\d+\.\d+)")
    image_versions = {
        match.group(1)
        for path in deployment_files
        for match in old_image.finditer(path.read_text(encoding="utf-8"))
    }
    if image_versions != {expected}:
        violations.append(
            f"Kubernetes image versions are {sorted(image_versions)}, expected {expected}"
        )
    if tag is not None and tag != f"v{expected}":
        violations.append(f"release tag is {tag}, expected v{expected}")
    return violations


def main() -> None:
    args = parse_args()
    violations = verify(args.expected, args.tag)
    if violations:
        raise SystemExit("Release version verification failed:\n- " + "\n- ".join(violations))
    print(f"Release version verified: {args.expected}")


if __name__ == "__main__":
    main()
