# Sky AWS/VM rehearsal provider

This separate wheel proves the deployment-provider packaging and pinning path
without activating an old AWS/VM migration. It contains one deterministic,
secret-free rehearsal registration. Secret values and SSH files are resolved
only at runtime from pinned external versions.

The packaged runtime and entrypoint evidence adapters deliberately fail closed.
Replacing them with reviewed, deployment-specific evidence collectors changes
the provider artifact digest and the descriptor pins, so a newly reviewed
manifest is required before an effect can run.

Build with `tools/build_wheel.py`. The build finalizer installs the static
execution descriptor into the wheel's `.dist-info` directory and updates
`RECORD`; an unfinalized setuptools wheel is not a valid Sky provider.
