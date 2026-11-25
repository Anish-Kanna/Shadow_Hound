#!/usr/bin/env python3
"""Create all __init__.py files for ShadowHound package structure."""
import os

packages = [
    "config",
    "db",
    "db/migrations",
    "agent",
    "api",
    "api/routers",
    "integrations",
    "integrations/edr",
    "integrations/siem",
    "integrations/threat_intel",
    "integrations/playbooks",
    "reports",
    "tests",
    "scripts",
]

base = os.path.dirname(os.path.abspath(__file__))
root = os.path.join(base, "..")

for pkg in packages:
    init_path = os.path.join(root, pkg, "__init__.py")
    os.makedirs(os.path.dirname(init_path), exist_ok=True)
    if not os.path.exists(init_path):
        with open(init_path, "w") as f:
            f.write("")

print("All __init__.py files created.")
