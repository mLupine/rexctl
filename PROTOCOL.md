# Rex wire protocol notes (API revision 7)

These are the parts of the Rex protocol that rexctl relies on, plus behaviour observed against real servers that the
spec does not state. Every Rex server publishes the authoritative spec itself: `GET /api/help` returns JSON with every
method and its schemas, and `GET /llms.txt` returns the prose version. When this file and the server disagree, the
server is right.

## Transport and identity

| Path | Purpose |
| --- | --- |
| `GET /api/help` | every method with JSON Schemas (`methods[]`, `block_types[].methods[]`) |
| `GET /llms.txt`, `/llms.html` | the full spec as text |
| `GET /api/control` | WebSocket, subprotocol `rex.control.v1`: method calls and events |
| `GET /api/data` | WebSocket, subprotocol `rex.data.terminal.v1`: one block's output stream (binary) |

- rexctl connects over HTTPS only, with certificate and hostname verification, and refuses URLs that carry
  `user:password@`.
- The client sends no credentials. The server identifies the caller from the connection, for example its Tailscale
  identity (`server.whoami` reports `principal.kind` and `transport`). An unknown principal gets HTTP 403 with a JSON
  body on every request; rexctl reports `access_denied` (exit 4) and does not retry.
- Each connection appears in the Rex apps as a client: `kind=agent`, `name=rexctl`, and `platform` from the local OS
  (`macos`, `linux`, `windows`, `freebsd` or `other`). With `event_scope=all`, other clients see `client_joined` and
  `client_left`.

## Control connection (`rex.control.v1`)

The client opens the WebSocket with `Sec-WebSocket-Protocol: rex.control.v1`. The server offers permessage-deflate but
works without it, and rexctl negotiates no extensions. All messages are JSON text frames. The server pings every 120 s.

1. Within 5 s the client sends
   `{"type":"hello","api_revision":7,"client":{"kind":"agent","platform":"macos","name":"rexctl","version":"0.1.0"}}`.
2. The server answers
   `{"type":"welcome","protocol":"rex.control.v1","limits":{"max_message_bytes":1048576},"client":{"id":...,"reconnect_token":...},"api_revision":7,...}`.
   rexctl never prints the reconnect token, and it refuses to send a message larger than `max_message_bytes`.
3. Request: `{"type":"request","id":"<unique>","method":"<name>","payload":{...}}`.
4. Response: `{"type":"response","id":"...","seq":N,"payload":{...}}`, or the same with `"error":{"code","message","status"}`.
   Codes include `bad_request` 400, `not_found` 404, `method_not_found` 404, `session_not_found` 404, `conflict` 409
   (for example, not attached), `refused` 403, `too_large` 413, `internal` 500 and `timeout` 504.
5. Event: `{"type":"event","seq":N,"payload":{"type":"<name>","payload":{...}}}`. Session events arrive wrapped as
   `{"type":"session_event","payload":{"session_id":...,"event":{"type":...,"payload":...}}}`, and block events as
   `block_event` inside that.

- Requests may be pipelined. Only the ordered methods (`block.event`, `client.key`, `session.new_*`, focus changes,
  `block.close` and similar) run one after another. rexctl pipelines independent reads (`call_many`), which matters on
  high-latency links.
- A close frame with 1000 ends the client at once. A dropped TCP connection keeps the client for 60 s.
- Reconnect: send the hello again with `client.reconnect_token`. rexctl then re-applies its attach scope and attached
  sessions. `seq` restarts at 1, and events sent during the gap are lost.

## Attaching

A method that names a `session_id` fails with `conflict` until the connection is attached. rexctl sends
`session.attach_all {"event_scope":"session"}`, which grants access to every session without joining any of them, so
rexctl is not listed in `session.list_clients`. `event_scope:"all"` adds `block_event` and the `client_*` events.

`session.attach {session_id}` joins one session. It is required for `data.connect`, `session.own_block` and
`session.disown_block`, and `client.key` needs an attached connection. rexctl uses it only for those, for `stream`, and for
`wait-for --text` and `--idle`.

## Terminal block methods

Block methods are called by full name, `com.superlogical.terminal.<method>`, with the payload
`{"session_id","block_id","args":{...}}`.

| Method | Arguments | Result and notes |
| --- | --- | --- |
| `format` | `format` (`text`, `html`, `vt`), `trim`, `unwrap`, `max_bytes` | `{content, id?, total?, eof?}`: the screen plus the full scrollback. Large output continues through `blob_read`. |
| `blob_read` | `id`, `offset`, `max_bytes` | `{id, data, total, eof}`. An offset inside a multi-byte character fails with `bad_request`. Results live about 5 minutes. |
| `clipboard_read` | `id`, `offset`, `max_bytes` | like `blob_read`; rexctl redacts `data` unless `--show` is given |
| `size` | | `{columns, rows, owner, ...}`; `rows` is the visible height |
| `title`, `pwd`, `process` | | `{title, owner}`; `{pwd}` as a `file://` URL or empty; `{child, foreground{pid,name,cwd,...}, ancestors}` |
| `program_status` | | `{records:[{state, kind, app, title, msg, updated_at}]}` with `state` one of `idle`, `working`, `done`, `blocked`, `error`. Coding agents report here. |
| `write` | `data` | types text as the user. Control bytes are allowed: `\r` is Enter, `\x03` is Ctrl-C. |
| `list_dir` | `path`, `prefix`, `limit`, `files` | `{path, home, status, entries}` |
| `modes`, `input_mode` | | terminal modes; `{echo, canonical, signals}` (echo off usually means a password prompt) |
| `resize` | `columns`, `rows` | takes effect at once only if the caller owns the block or nobody does |
| `set_theme`, `reset`, `clear` | | change the terminal; `clear` also drops scrollback |

rexctl treats `blob_read` and `clipboard_read` as sensitive, because either can return clipboard text: the wrappers
redact it and a raw `api call` of either is guarded.

## Sessions and layout

- `session.list` returns `{sessions:[{session_id,label}]}`. `session.view {session_id}` returns windows, layers and blocks
  (`creator_name`, `flavor`, `label`, `owner`), `active_window_id` and each window's `focused_block_id`.
- `session.create {label, initial_windows:[{layout:{block:{flavor:"com.superlogical.terminal.shell",options:{cwd}}}}]}`
  returns `{session_id, initial_windows:[{window_id, block_ids}]}`. The session survives the creating connection.
- `session.new_split {session_id, anchor_id, direction, side, layout, focus}`, `block.close {session_id, block_id}`,
  `session.destroy {session_id}`.
- The layout methods behind `rexctl layout` all take `session_id`: `new_window`, `new_block` (detached), `new_layer`,
  `move_block`, `move_window`, `move`, `swap_blocks`, `resize_pane`, `resize_layer`, `float_block`, `zoom_block`, the
  `focus_*` family, `close_window`, `close_layer` (tiled layers are rejected), `set_label`, `set_window_label`,
  `set_block_label`, `lower_layer` and `raise_layer`. `bounds` is `[x, y, w, h]` in fractions of the window. A layout node
  is `{block:{flavor,options,label}}` or `{split:{direction,before,after,ratio}}`.
- `session.own_block` (mode `take` or `request`) makes the caller's terminal size win until its connection ends.
  `session.detach_block` takes a block out of its window, closing the window or layer if it was the last block.

## Input events

`block.event {session_id, block_id, event:{type, payload}}` accepts only `key`, `paste` (`{text}`), `mouse`, `wheel`
and `focus` (`{action:"in"|"out"}`). A key payload is the same object as `client.key`'s `key`:

```json
{"key":"key_c","mods":"ctrl","consumed_mods":"","text":"","unshifted_codepoint":99,"composing":false,"action":"press"}
```

`key` is the W3C key code in snake case, and `mods` joins `shift`, `ctrl`, `alt` and `super` with `+` in that order.
`client.key {session_id, block_id?, key, prefix?}` lets the client's key bindings handle the key first and returns
`{handled}`. The spec does not define mouse and wheel payloads; rexctl passes them through unchanged.

## Events

`rexctl events` prints each event as `{"host","seq","name","session_id","block_id","payload"}`. Names include
`session_created`, `session_destroyed`, `session_view_changed`, `block_created`, `block_closed`, `window_*`,
`client_joined`, `client_left`, `tailscale_status_changed`, `hosts_changed` and `keymap_changed`. Block events seen with
`event_scope=all` include `bell`, `title_changed {title, owner}`, `process_changed`, `pwd_changed {pwd, owner}`,
`program_status_changed` and `child_exited`. `pwd_changed` fires only when the shell sends OSC 7.

`wait-for --status`, `--closed`, `--bell`, `--title-changed`, `--cwd-changed`, `--child-exited` and `--event` all watch
this event stream. With `--no-stream`, `--status` polls `program_status` and `--closed` polls `session.list_blocks` instead.

## Data stream (`rex.data.terminal.v1`)

The data stream is a read-only copy of one block's output.

1. `session.attach {session_id}`. This joins the session, so the Rex apps list rexctl as a client while the stream is
   open. `attach_all` is not enough. Owning the block is not needed, and rexctl never claims one.
2. `data.connect {session_id, block_id, data_ref_id:"terminal", subprotocol:"rex.data.terminal.v1"}` returns
   `{ticket, expires_in_ms}`. The ticket is 22 base64url characters (16 bytes), single use, valid for 60 s, and bound to
   the caller.
3. Open `GET /api/data` with subprotocol `rex.data.terminal.v1` and, within 5 s, send the binary HELLO: `0x01` followed by
   the 16 ticket bytes.
4. The server answers with one binary message. WELCOME is 32 bytes: `0x81`, a 16-byte resume token, 3 zero bytes,
   `keep_ms` as u32 little-endian, and `nonce` as u64 little-endian. REJECT is `0x82` followed by a reason:

   | Reason | Meaning |
   | --- | --- |
   | 1 | ticket or token unknown, expired, used, issued to someone else, or the session is gone |
   | 2 | this client already has a connection to this data source |
   | 3 | stream unavailable (block closed, or the resume byte count is too low) |
   | 4 | limit reached, try later |
   | 5 | malformed or late handshake, or the resume byte count is too high |
   | 6 | server failure |
   | 7 | ticket issued for a different subprotocol |

5. Every later binary message (1 byte to 64 KiB) continues the stream. Data the client sends after WELCOME is ignored;
   input goes through `write`, `block.event` or `client.key` on the control connection.

The stream starts with a terminal snapshot (opaque binary) followed by program output. Rex messages are embedded as
APC sequences, `ESC _ rex1;<nonce>;<json> ESC \`, using the WELCOME nonce. Types include `resize`, `theme` and
`child_exited`. Sequences with another nonce are program output. The first Rex message after the snapshot is always
`resize`, so rexctl skips everything before it. An unterminated Rex message is dropped after 1 MiB.

**Resume.** On a new socket, send RESUME: `0x02`, the latest token, and the count of every stream byte received so far
as u64 little-endian (the snapshot counts, WELCOME does not). The server answers with a new WELCOME and token and the
same nonce. Resume after close 1001 (keepalive timeout) or a dropped TCP connection; the server keeps the stream for
60 s. Close 4000 (block closed), 1013 (reconnect required), 1008 and 1011 are final.

**Observed, not in the spec.** After an abrupt client-side TCP drop the server sometimes rejects RESUME with reason 3
even when the byte count is exact, because bytes it already wrote cannot be replayed. rexctl retries RESUME a few times
on reasons 2 and 3, then asks `data.connect` for a fresh ticket, opens a new stream, skips its snapshot and reports a
`gap` item.

**Text view.** rexctl strips CSI, OSC, DCS and APC sequences and control codes, turns `\r\n` into `\n`, and turns a lone
`\r` before printable text into `\n`. The result is a log of output, not a screen: full-screen programs repeat text as
they redraw. `screen` and `tail` give the exact screen.

`wait-for --text` waits for a burst of output to settle (100 ms), then searches the stream text (the last 1 MiB) and
re-reads the screen and scrollback with `format`. With `--new` it searches only the stream, so text that was already on
screen does not count. `--idle` waits until no output arrives for the given time.

## Server administration

`server.status`, `hosts.list`, `hosts.put`, `hosts.remove`, `client.list`, `client.inspect`, `client.set_label`,
`client.perform` and `client.action` work over the network. `client.list` keeps a client's label in `info.label`, and
Unix-socket clients have no `info`.

`server.stop`, `server.config_reload`, `server.tailscale.*` and `server.apple.*` are server-local. Over the network the
server answers 403 with `code=internal` and a message that the method requires the local Unix socket; rexctl reports
that as `local_only` (exit 5). Other 401 and 403 responses are `access_denied` (exit 4).

`target.resolve` tries the full id, the label, the window position and then the id tail. It rejects `scope` when
`kinds` includes `session` (400 `bad_request`). The server does not match terminal titles; rexctl does that itself, and
only for exact titles.

## rexctl's own protocols

**Daemon socket.** Newline-delimited JSON over a Unix socket that only the owning uid may use. A request is
`{op, url, timeout, ...}` with `op` one of `open` (returns the welcome without the reconnect token), `call {method,
payload}` and `call_many {calls}`, or one of the control ops `ping`, `status` and `stop`. A reply is `{ok:true, ...}` or
`{ok:false, error:{kind, message, ...}}`, with the same kinds and details as the CLI's error JSON.

**MCP server.** Each tool call runs the CLI in-process with stdout and stderr captured. Exit 0 and 10 (dry run) are
successes; any other code returns `isError: true` with the CLI's error JSON. A changing tool appends
`--yes-i-am-authorised=<plan_id>` only when `confirm` is a non-empty string. The CLI then acts only if the re-resolved
plan has that id. Connections are pooled inside the MCP process. `rex_events_since` keeps one collector thread per host:
`attach_all` with scope `all`, clipboard text redacted, the last 2000 events, a monotonic `cursor`, `gap: true` when the
requested cursor has been dropped, and marker events when the collector hits an error.

## Differences from the official `rex` CLI

rexctl has no Lua, no `rex do`, no rendering of the data stream (the snapshot is skipped, not parsed), no host or login
management and no QUIC transport.
