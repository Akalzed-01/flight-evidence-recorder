# Security policy

## Scope

The project treats capsules, repositories, and process output as potentially hostile data. v1 is not a sandbox, does not execute an imported capsule, and does not provide a public server.

## Defaults

- `shell=False`, `stdin=DEVNULL`, and an explicit allowlist of absolute executable paths.
- A minimal environment; values from authorized environment variables are redacted before persistence, without a guarantee of anonymization.
- Git is observed only through read-only commands with external helpers disabled.
- Arguments, environment values, and streams are redacted before persistence.
- Time and size limits apply to processes, Git, and imported capsule reads.
- `inspect`, `serve`, `plan`, and `verify` do not start processes.
- `serve` accepts loopback connections only, supports `GET` and `HEAD`, and uses a temporary URL token.

## Do not submit secrets

Do not attach real capsules to issues or pull requests. Redaction is best effort and is not anonymization, compliance, or secure deletion.

## Reporting

For a vulnerability, use GitHub's private vulnerability reporting channel for this repository when available. Do not open a public issue with exploit details, real capsules, tokens, or personal data. If private reporting is unavailable, contact the maintainer privately before disclosure.
