"""Fail a release when transmit-capable field probing code or unsafe defaults appear."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BANNED_SENSOR_MODULES = {"socket", "subprocess"}
BANNED_SCAPY_SYMBOLS = {"send", "sendp", "sendpfast", "sr", "sr1", "srp", "srp1"}
BANNED_TRANSMIT_CALLS = {"connect", "connect_ex", "send", "sendall", "sendto"}
BANNED_PROBING_MODULES = {
    "httpx",
    "requests",
    "scapy",
    "socket",
    "subprocess",
    "urllib",
}


def top_level(module: str | None) -> str:
    return (module or "").split(".", 1)[0]


def scan_python_file(path: Path, area: str) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = {top_level(alias.name) for alias in node.names}
            banned = BANNED_SENSOR_MODULES if area == "sensor" else BANNED_PROBING_MODULES
            for module in sorted(modules & banned):
                violations.append(f"{path}: forbidden {area} import: {module}")
        elif isinstance(node, ast.ImportFrom):
            module = top_level(node.module)
            names = {alias.name for alias in node.names}
            if area == "sensor" and module in BANNED_SENSOR_MODULES:
                violations.append(f"{path}: forbidden sensor import: {module}")
            if area == "probing" and module in BANNED_PROBING_MODULES:
                violations.append(f"{path}: forbidden probing import: {module}")
            if module == "scapy" and ("*" in names or names & BANNED_SCAPY_SYMBOLS):
                violations.append(f"{path}: transmit-capable Scapy import: {sorted(names)}")
        elif area == "sensor" and isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in BANNED_TRANSMIT_CALLS:
                violations.append(f"{path}:{node.lineno}: forbidden sensor transmit call")
    return violations


def required_text(path: Path, snippets: tuple[str, ...]) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [
        f"{path}: missing passive-release invariant: {snippet}"
        for snippet in snippets
        if snippet not in text
    ]


def verify_repository() -> list[str]:
    violations: list[str] = []
    sensor_root = ROOT / "sensor" / "src" / "ot_sentinel_sensor"
    for path in sensor_root.glob("*.py"):
        violations.extend(scan_python_file(path, "sensor"))
    probing_path = ROOT / "backend" / "app" / "probing.py"
    violations.extend(scan_python_file(probing_path, "probing"))
    violations.extend(
        required_text(
            probing_path,
            (
                '"executor_available": False',
                '"transmission_capable": False',
                '"transmission_performed": False',
                '"allowed": False',
                '"probe_executor_not_installed"',
            ),
        )
    )
    deployment_invariants = {
        ROOT / ".env.example": ("ACTIVE_PROBING_ENABLED=false",),
        ROOT / "docker-compose.yml": ("ACTIVE_PROBING_ENABLED:-false",),
        ROOT / "deploy" / "kubernetes" / "base" / "config.yaml": (
            'ACTIVE_PROBING_ENABLED: "false"',
        ),
    }
    for path, snippets in deployment_invariants.items():
        violations.extend(required_text(path, snippets))
    unexpected = [
        path
        for root in (ROOT / "backend" / "app", sensor_root)
        for path in root.glob("*probe*executor*.py")
    ]
    violations.extend(
        f"{path}: probe executor module is prohibited in passive releases" for path in unexpected
    )
    return violations


def main() -> None:
    violations = verify_repository()
    if violations:
        raise SystemExit("Passive release verification failed:\n- " + "\n- ".join(violations))
    print(
        "Passive release verified: no field-probe executor or "
        "transmit-capable sensor path found."
    )


if __name__ == "__main__":
    main()
