# Contributing

1. Create a virtual environment and install the package in editable mode.
2. Run `python -m unittest discover -s tests -v` before and after your change.
3. Add a synthetic fixture for any change to the capsule format.
4. Do not include tokens, personal paths, real logs, or user files.
5. Preserve the rule that `replay --verify` never calls `Popen`.

Schema changes require a golden test vector, a compatibility note, and an update to `docs/capsule-format.md`.
