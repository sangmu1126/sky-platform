# Sky AWS/VM rehearsal provider

This separate wheel proves the deployment-provider packaging and pinning path
without activating an old AWS/VM migration. It contains one deterministic,
secret-free rehearsal registration. Secret values and SSH files are resolved
only at runtime from pinned external versions.

The packaged runtime and entrypoint evidence adapters deliberately fail closed.
Replacing them with reviewed, deployment-specific evidence collectors changes
the provider artifact digest and the descriptor pins, so a newly reviewed
manifest is required before an effect can run.

Build with:

```sh
python -I tools/build_wheel.py --output-dir <wheel-directory>
```

The build finalizer installs the static execution descriptor into the wheel's
`.dist-info` directory, updates `RECORD`, and writes the final wheel with mode
`0400`. An unfinalized setuptools wheel is not a valid Sky provider. Build and
installation verification tools require Python isolated mode and run pip
offline without ambient user configuration.

Verify the exact base and provider wheels before deployment:

```sh
python -I tools/verify_installation.py \
  --base-wheel <sky-platform-wheel> \
  --provider-wheel <provider-wheel>
```

The verifier makes two independent no-bytecode installations, seals installed
files to `0400` and directories to `0500`, disables ordinary Python socket
network access, renders the secret-free worker manifest, runs `--check-config`,
and composes only the descriptor-approved registration. Preserve the reported
base wheel, provider wheel, and provider artifact SHA-256 values as one reviewed
deployment set. The result also reports `runtime_chain_pins_match=true` only
when the resolver, composer, runtime, effect, and execution revision form one
internally consistent chain.

Install reviewed provider wheels with `python -m pip install --no-compile`.
Sky rejects provider bytecode caches and disables bytecode writes before
loading provider code so artifact pins stay independent of the installation
path while every executable source and packaged data file remains attested.

Production installation is stricter than a local verifier run. Install the
base and provider distributions under an operator-owned identity (normally
root), remove every write bit from the provider distribution tree, and run the
worker as a different non-root identity. Install the absolute worker manifest
as a non-writable regular file, normally mode `0400`. Read-only mode bits alone
do not stop a file owner from restoring write permission, and the Python socket
guard is not an OS network sandbox. Deployment policy must provide those OS
ownership and network boundaries.

This wheel remains a packaging rehearsal: its runtime and entrypoint evidence
adapters fail closed. Successful installation verification does not activate
AWS, VM, database, router, or migration effects.
