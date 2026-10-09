#!/usr/bin/env python3
"""Export the verified OCI identity in the deployment repository's lock format."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil


def required(name, pattern):
    value = os.environ[name]
    if re.fullmatch(pattern, value) is None:
        raise ValueError(f"Invalid {name}")
    return value


def main():
    repository = required("GITHUB_REPOSITORY", r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
    image = required("IMAGE", r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+")
    if image != "ghcr.io/" + repository.lower():
        raise ValueError("Image must belong to the source repository")
    digest = required("DIGEST", r"sha256:[0-9a-f]{64}")
    commit = required("GITHUB_SHA", r"[0-9a-f]{40}")
    ref = required("GITHUB_REF", r"refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?)")
    workflow_commit = required("WORKFLOW_COMMIT", r"[0-9a-f]{40}")
    document = {
        "schema": 1,
        "services": {
            "hiro-proxy": {
                "image": image,
                "digest": digest,
                "source_repository": repository,
                "source_commit": commit,
                "source_ref": ref,
                "build_workflow": ".github/workflows/ci.yml",
                "workflow_commit": workflow_commit,
                "runtime_profile": "hiro.gcp-tdx.v1",
            }
        },
    }
    output = Path("dist")
    output.mkdir(exist_ok=True)
    (output / "images.lock.json").write_text(json.dumps(document, indent=2) + "\n")
    (output / "image-ref.txt").write_text(f"{image}@{digest}\n")
    (output / "image-digest.txt").write_text(digest + "\n")
    shutil.copyfile(os.environ["PROVENANCE_BUNDLE"], output / "image.sigstore.json")
    (output / "release-notes.md").write_text(
        f"Hiro proxy `{commit}`\n\nImage: `{image}@{digest}`\n\n"
        "Runtime profile: `hiro.gcp-tdx.v1`. Linux amd64, UID/GID 65532, port 8080.\n\n"
        "Import `images.lock.json` with its Sigstore bundle into the hiro release repository. "
        "Deploy the digest, never a mutable tag. The guest runtime contract is in "
        "`docs/GCP_TDX.md` at the source commit.\n"
    )
    files = sorted(output / name for name in (
        "images.lock.json", "image-ref.txt", "image-digest.txt", "image.sigstore.json",
    ))
    (output / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files
    ))
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
        summary.write(f"## Published proxy image\n\n`{image}@{digest}`\n\n")
        summary.write("Download the image metadata artifact for the `hiro` deployment lock.\n")


if __name__ == "__main__":
    main()
