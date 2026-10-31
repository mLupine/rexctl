# Contributing

rexctl has no runtime dependencies and should keep it that way. Tests and linters are development tools only.

## Running the tests

```sh
uv run --only-group dev pytest -q                  # offline
uv run --only-group dev pytest -q --live studio    # also the live tests, against a host label or URL
uv run --only-group dev ruff check . && uv run --only-group dev ruff format --check .
uv run --only-group dev mypy                       # strict, configured in pyproject.toml
```

The offline suite talks to an in-process fake server over a real socket pair, so it covers the WebSocket framing as
well as the commands. The live tests create `rexctl-selftest-*` sessions on the server you name, type into them and
destroy them when they finish, even when a test fails.

## What a change needs

- A test that calls the command or function the way a user would and checks the result. A test that would still pass
  with the code removed is not a test.
- For a new server method: a wrapper (usually one `Op` entry in `rexctl/ops.py`), a row in `COVERAGE.md`, and, when it
  changes state, a dry run. `tests/test_coverage.py` fails until the method is wrapped or listed as excluded.
- For anything that changes state over MCP: the `plan_id` flow, and no new way to pass authorising flags through
  `args`.
- Updated docs when behaviour changes. `PROTOCOL.md` records what the server actually does, not what its help text
  says.

## Updating the method list

`fixtures/help-methods.json` is the list of methods the coverage test checks against. When the server's API revision
changes, regenerate it from `GET /api/help` (names and block methods only) and update `COVERAGE.md`.

## Releasing

The version lives only in `rexctl/__init__.py`. To release:

1. Set `__version__` and rename the `## Unreleased` heading in `CHANGELOG.md` to that version. Commit and push.
2. Tag the commit and push the tag:

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

`.github/workflows/release.yml` then runs the full CI, checks that the tag matches `__version__`, builds the wheel, the
sdist and the `.pyz` zipapp, smoke-tests the wheel and the zipapp, and publishes a GitHub release with those files,
`SHA256SUMS`, and the changelog section as its notes. A tag that does not match `__version__`, or a version with no
changelog section, fails the run before anything is published.
