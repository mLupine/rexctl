# Changelog

## 0.1.0

First public version.

- Dry runs of `send`, `split` and `kill` show the block's label, title, working directory and program.
- Guarded commands bind to a plan: a dry run prints a `plan_id`, and `--yes-i-am-authorised=PLAN_ID` acts only if the
  target and payload still produce that id. MCP `confirm` takes the `plan_id` instead of `true`.
- `api call` of a method rexctl does not wrap needs `--allow-server-admin` as well.
- Option abbreviations are off, so a prefix such as `--yes` can no longer stand in for an authorising flag.
- MCP `args` accept only the flags of the chosen verb. Authorising flags, `--show*` and file arguments are refused.
- MCP results that carry terminal text include an `untrusted` note. Large results are shortened but stay valid JSON.
- MCP refuses `@file` values, so a tool call cannot read local files. NaN and infinite numbers are refused, and
  `host` must be a label from the hosts file.
- `--where` filters run after clipboard redaction. `send --secret-file` no longer prints a hash of the secret.
- Block titles match only exactly. Id fragments must be a prefix or suffix of at least 4 characters.
- WebSocket client: fragmented and interleaved control frames, masked or reserved-bit frames refused, close frames
  answered, HTTP response heads capped at 16 KiB, outgoing messages kept under the server's size limit.
- The daemon takes a lock before it binds, so two concurrent starts cannot replace each other's socket.
- The daemon checks the peer uid correctly on Linux and macOS, refuses a cache directory it does not own or that others
  can read, and no longer writes a pid file.
- `send --secret-file`, `wait-for --new`, and the key names `comma`, `plus` and `minus`.
- `events` and `stream` reconnect the control connection when it drops.
- Unexpected errors exit with code 1 and a traceback on stderr instead of a raw crash.
- No built-in hosts. Labels come from `$REXCTL_HOSTS` or `$XDG_CONFIG_HOME/rexctl/hosts.json`.
- Licensed under GPL-3.0-or-later.
- Tagged versions publish a GitHub release with the wheel, the sdist and a single-file `.pyz` zipapp.
