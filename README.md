# rexctl

rexctl is a command-line client for the Rex terminal server. It reads screens, waits for output, follows events,
types into terminals and rearranges layouts, and it prints one JSON object per line so scripts and AI agents can use
it. It also runs as an MCP server.

It is an unofficial, independent client. It talks to the public Rex API (revision 7) and has no affiliation with the
Rex authors.

- Python 3.11 or newer, standard library only.
- Connects over HTTPS only and verifies certificates.
- Everything that changes state is a dry run until you pass `--yes-i-am-authorised`, normally with the id of the plan
  you approved.

## Install

```sh
pipx install git+https://github.com/mLupine/rexctl
# or: uv tool install git+https://github.com/mLupine/rexctl
```

From a checkout, `python -m rexctl` works without installing anything.

## Configure hosts

rexctl does not know any servers until you name them. Put labels in `~/.config/rexctl/hosts.json`
(`$XDG_CONFIG_HOME/rexctl/hosts.json`, or any file named by `$REXCTL_HOSTS`):

```json
{
  "studio": "https://studio-rex.example.ts.net",
  "laptop": "https://laptop-rex.example.ts.net"
}
```

Every command takes `-H LABEL` or `-H https://...`. `$REXCTL_HOST` sets the default. rexctl sends no credentials of its
own: the Rex server decides who you are from the connection, for example your Tailscale identity.

```sh
rexctl hosts --check          # which hosts answer, and whether they let you in
rexctl -H studio version      # server version, who the server thinks you are, API revision
```

## Quick start

```sh
rexctl -H studio ls                                   # sessions, windows and blocks with title, cwd, program
rexctl -H studio screen -t work//build --text         # the visible screen of the block titled "build"
rexctl -H studio wait-for -t work//build --text 'tests? (passed|failed)' --wait-timeout 300
rexctl -H studio events --filter bell,exit --duration 60
```

Typing into a terminal takes two steps:

```sh
rexctl -H studio send -t work//build --text 'make test' --enter
# {"ok": true, "dry_run": true, "plan_id": "3f9c0a1b2d4e", "action": "send input to terminal", "target": {...}, ...}

rexctl -H studio send -t work//build --text 'make test' --enter --yes-i-am-authorised=3f9c0a1b2d4e
```

The dry run also shows an `about` field with the block's label, title, working directory and foreground program, so
you can tell which pane it is. Those come from the terminal and are not part of the id.

The second run resolves the target again and only acts if the plan still has the same id. If the focused block
changed, a block closed, or a different pane now matches the name, you get a fresh dry run instead.
`--yes-i-am-authorised` without an id also works, for a human at a keyboard who can see what they are hitting.

## How it behaves

- **Output.** stdout carries JSON lines, each with `"ok": true` or `false`. Diagnostics go to stderr. `screen`, `tail`
  and `stream` accept `--text` for plain text.
- **Dry runs.** `send`, `new-session`, `split`, `kill`, `api call` of a method that changes state, and the changing verbs
  of `layout`, `input`, `term`, `conn` and `onboarding` print a plan with a `plan_id` and exit with code 10. Server
  administration (`admin server-stop`, `admin tailscale-*`, `admin hosts-put` and the like, or the same methods through
  `api call`) also needs `--allow-server-admin`.
- **Secrets.** Keys named like tokens, tickets, secrets or passwords are masked in all output. Clipboard text in events
  and reads is redacted unless you ask for it. `send --secret-file FILE` types a file's contents while the plan shows
  only its length.
- **No option abbreviations.** `--yes` is not `--yes-i-am-authorised`. Every flag must be spelled in full.
- **Values that start with a dash** need the `=` form: `send --text=-rf`, not `send --text -rf`.

[SECURITY.md](SECURITY.md) explains what these guards protect against and what they do not.

## Choosing a target

`-s` picks a session and `-b` a block. `-t SESSION[/WINDOW[/BLOCK]]` does both in one string, and an empty part
means the default.

| Part | Accepts |
| --- | --- |
| session | id, label, unique label prefix, or an id prefix or suffix of at least 4 characters. Optional when only one session exists. |
| window | id, label, position (`1`, `2`, ...) or `active` |
| block | id, label, id prefix or suffix, or the exact terminal title (case-insensitive). Defaults to the focused block of the active window. |

`work//build` means the block named or titled `build` in any window of session `work`. Labels win over titles. An
ambiguous name is an error (exit 6) that lists the candidates. Titles match only exactly because any program can set
its own title.

## Commands

### Reading

| Command | Output |
| --- | --- |
| `hosts [--check]` | configured hosts; `--check` connects and reports access and version |
| `version` | `server.version`, `server.whoami` and the API revision |
| `ls [-s S] [--brief]` | sessions, windows and blocks with title, cwd, foreground program and program status (`--brief` skips the per-terminal lookups) |
| `screen [--lines N] [--unwrap] [--text]` | the visible screen, trimmed |
| `tail [--lines 200] [--unwrap] [--text]` | the last lines of scrollback |
| `pwd`, `title`, `process`, `status` | one terminal fact; `status` reports the program status protocol, for example a coding agent's `working`, `blocked` or `done` |
| `api list`, `api describe METHOD` | the server's method list from `GET /api/help` |
| `api call METHOD [JSON or @file]` | any method; read-only methods run at once, the rest are guarded, and methods rexctl does not wrap also need `--allow-server-admin` |

### Waiting and watching

`wait-for` blocks until one condition holds and exits with 7 on timeout (`--wait-timeout`, default 60 s):

| Condition | Source |
| --- | --- |
| `--text REGEX` | screen and live output; add `--new` to ignore what is already on screen |
| `--idle SECONDS` | no output for that long |
| `--status done,blocked` | program status events |
| `--closed`, `--bell`, `--child-exited` | block events |
| `--title-changed [REGEX]`, `--cwd-changed [REGEX]` | title and working-directory events |
| `--event NAME [--where PATH=VALUE or PATH~REGEX]` | any server or block event |

`--no-stream` polls the screen instead of reading the live data stream.

`events` streams server events as JSON lines (`host`, `seq`, `name`, `session_id`, `block_id`, `payload`).
`--filter` takes event names or the aliases `cwd`, `title`, `status`, `exit` and `closed`. `--where` filters on payload
fields. Block events switch the scope to all sessions. A dropped connection is resumed with the reconnect token, and a
`rexctl_reconnected` line marks the gap.

`stream` prints a block's live output as `data`, `rex`, `screen`, `gap` and `end` lines, or plain text with `--text`.
While it runs, rexctl is attached to the session as a client.

### Changing things (guarded)

| Command | Effect |
| --- | --- |
| `send [--text T or --secret-file F] [--enter] [--keys "C-c Up Enter"]` | types into a terminal as the user |
| `new-session [--label L] [--cwd D]` | a new session with one shell |
| `split [--direction horizontal or vertical] [--label L] [--cwd D]` | splits a block with a new shell |
| `kill [--whole-session]` | closes a block, or destroys the session |
| `layout VERB` | windows, blocks, layers, focus and labels: `new-window`, `move-block`, `swap-blocks`, `zoom-block`, `focus-direction`, `close-window`, `set-block-label` and more |
| `input key/paste/focus/mouse/wheel/event` | structured input events, sent to the block or (`input key --via client-key`) through the client's key bindings |
| `term VERB` | terminal methods: read-only `modes`, `input-mode`, `size`, `list-dir`; guarded `resize`, `reset`, `clear`, `set-theme`; `clipboard-read` and `blob-read` redact unless `--show` |
| `conn VERB` | attach, block ownership and block description. Ownership lasts as long as the connection: one call without the daemon, up to the idle timeout with it. |
| `target resolve`, `target complete` | the server's own name resolver |
| `onboarding state`, `onboarding set-step` | the onboarding walkthrough block |
| `admin VERB` | server status, host list, clients, key map (read-only); config reload, stop, Tailscale and host-list changes (two flags) |

`rexctl GROUP VERB --help` lists each verb's flags. Key names for `--keys`: `Enter`, `Esc`, `Tab`, `Backspace`, `Space`,
arrows, `Home`, `End`, `PageUp`, `PageDown`, `Insert`, `Delete`, `F1` to `F25`, `comma`, `plus`, `minus`, any single
character, with modifiers `C-`/`ctrl+`, `M-`/`alt+`, `S-`/`shift+` and `super+`. `send --keys` turns them into terminal
bytes; `F13` and above only exist as structured events (`input key`).

Server-local methods (`server-stop`, `server-config-reload`, `tailscale-*`, `privacy-status`) are accepted only on the
server's Unix socket. Over the network the server answers 403 and rexctl exits with 5 (`local_only`).

## Daemon

```sh
rexctl daemon start     # or: run (foreground), status, stop
```

The daemon keeps one connection per host open behind a private Unix socket in `~/.cache/rexctl` (directory 0700, socket
0600, and the peer's uid must match). Request/response commands use it automatically when it runs, which cuts a command
from about 3 s to well under 1 s on a slow link. Streaming commands (`events`, `wait-for`, `stream`) always open their own
connection. `--no-daemon` or `REXCTL_NO_DAEMON=1` bypasses it, and `REXCTL_CACHE_DIR` moves its directory.

It resumes dropped connections with the server's reconnect token, which never leaves the daemon. It closes a host
connection after `--upstream-idle` seconds (default 900) and reopens it on demand. A request that may already have
reached the server is never retried.

## MCP server

```json
{"mcpServers": {"rex": {"command": "rexctl", "args": ["mcp"]}}}
```

Read-only tools run at once: `rex_hosts`, `rex_ls`, `rex_screen`, `rex_tail`, `rex_status`, `rex_wait_for` (up to
120 s), `rex_events_since` (a background collector with a cursor), `rex_server_info` and `rex_op_catalog`.

Tools that change state (`rex_send`, `rex_new_session`, `rex_split`, `rex_kill`, and `rex_op` for any `layout`, `input`,
`term`, `onboarding`, `conn` or `target` verb) return a dry-run plan. They act only when called again with the same
arguments and `confirm` set to that plan's `plan_id`. `host` must be a label from the hosts file. `@file` values,
the authorising flags, `--show*`, `--hosts-file` and
`--auth-key-file` cannot be passed through `args`, and server administration is not exposed at all. Read results
include an `untrusted` note, because programs in the terminal wrote much of that text.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | ok |
| 1 | error, including unexpected internal errors (`kind: internal`, traceback on stderr) |
| 2 | usage |
| 3 | unreachable (DNS, TCP, TLS, no WebSocket upgrade) |
| 4 | access denied: the server refused this identity (HTTP 401/403) |
| 5 | API error (`bad_request`, `not_found`, ...), or `local_only` |
| 6 | target not found or ambiguous |
| 7 | timeout |
| 10 | dry run, nothing changed |

## As a library

```python
from rexctl.connection import connect

with connect("https://studio-rex.example.ts.net") as conn:
    sessions = conn.call("session.attach_all", {"event_scope": "session"})["sessions"]
    view = conn.call("session.view", {"session_id": sessions[0]["session_id"]})
```

The module layout is not a stable API yet.

## Known limits

- When the server refuses to resume a data stream (it can after a hard TCP drop), `stream` and `wait-for` open a new
  one and print a `gap` line. Output during the gap may be missing. Events during a control reconnect are lost.
- `pwd_changed` fires only when the shell sends OSC 7, so `--cwd-changed` can time out on shells that do not.
- `send --keys` writes terminal bytes, so programs that use the kitty keyboard protocol see legacy sequences. Use
  `input key` for structured key events.
- `term resize` records this client's wanted size; the client that owns the block decides the real size.
- Every connection shows up in the Rex apps as an `agent` client.
- Four methods are deliberately not wrapped; [COVERAGE.md](COVERAGE.md) lists every method and its command.

[PROTOCOL.md](PROTOCOL.md) has the wire-level notes. [docs/agent-skill.md](docs/agent-skill.md) is a ready-made
instruction file for AI agents that use rexctl.

## Development

```sh
uv run --only-group dev pytest -q                  # offline; the live tests are skipped
uv run --only-group dev pytest -q --live studio    # also the live tests, against a real server
uv run --only-group dev ruff check .
uv run --only-group dev mypy
```

The live tests create throwaway `rexctl-selftest-*` sessions, type into them and always destroy them. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
