"""Expose upstream workspace dependency aliases to Cargo-aware derive macros."""

def _macro_manifest_impl(ctx):
    manifest = ctx.actions.declare_file(ctx.label.name + "/Cargo.toml")
    environment = ctx.actions.declare_file(ctx.label.name + ".env")
    ctx.actions.run_shell(
        inputs = [ctx.file.package_manifest, ctx.file.workspace_manifest, ctx.file._script],
        outputs = [manifest],
        command = 'python3 "$1" "$2" "$3" "$4"',
        arguments = [ctx.file._script.path, ctx.file.package_manifest.path, ctx.file.workspace_manifest.path, manifest.path],
        mnemonic = "CargoMacroManifest",
    )
    ctx.actions.write(environment, "CARGO_MANIFEST_DIR=${pwd}/" + manifest.dirname + "\n")
    return [
        DefaultInfo(files = depset([manifest, environment])),
        OutputGroupInfo(environment = depset([environment])),
    ]

macro_manifest = rule(
    implementation = _macro_manifest_impl,
    attrs = {
        "package_manifest": attr.label(allow_single_file = True, mandatory = True),
        "workspace_manifest": attr.label(allow_single_file = True, mandatory = True),
        "_script": attr.label(default = Label("//build:macro_manifest.py"), allow_single_file = True),
    },
)
