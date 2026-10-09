"""Create compile-time metadata from unmodified upstream Cargo manifests."""
import json
from pathlib import Path
import sys
import tomllib


def toml(value):
    if isinstance(value, dict):
        return "{ " + ", ".join(json.dumps(k) + " = " + toml(v) for k, v in value.items()) + " }"
    if isinstance(value, list):
        return "[" + ", ".join(toml(v) for v in value) + "]"
    return json.dumps(value)


package_path, workspace_path, output_path = map(Path, sys.argv[1:])
package = tomllib.loads(package_path.read_text())
workspace = tomllib.loads(workspace_path.read_text())["workspace"]
# proc-macro-crate inspects dependency names in CARGO_MANIFEST_DIR. Bazel
# already supplies the actual dependencies; only their inherited aliases need
# resolving here. This changes no upstream Rust or dependency selections.
version = package["package"]["version"]
if isinstance(version, dict) and version.get("workspace") is True:
    version = workspace["package"]["version"]
lines = ["[package]", "name = " + toml(package["package"]["name"]), "version = " + toml(version)]
for section in ("dependencies", "dev-dependencies", "build-dependencies"):
    lines.append("\n[" + section + "]")
    for name, dependency in package.get(section, {}).items():
        if isinstance(dependency, dict) and dependency.get("workspace") is True:
            dependency = workspace["dependencies"][name]
        lines.append(json.dumps(name) + " = " + toml(dependency))
output_path.write_text("\n".join(lines) + "\n")
