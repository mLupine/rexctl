# API coverage

Every method of Rex API revision 7: 73 server methods, 16 methods of the `com.superlogical.terminal` block and 2 of
the `com.superlogical.onboarding` block, 91 in total. rexctl wraps 87 and leaves 4 out on purpose. The 4 can still be
called with `rexctl api call`, which needs both `--yes-i-am-authorised` and `--allow-server-admin` for them.

`tests/test_coverage.py` keeps this honest: it runs every command against a fake server, records the methods each one
sends, and fails if a method in `fixtures/help-methods.json` is neither wrapped nor listed under the exclusions below.

| Class | Meaning |
| --- | --- |
| read | runs at once |
| guarded | a dry run that prints a `plan_id` until `--yes-i-am-authorised` (MCP: `confirm` set to that `plan_id`) |
| two flags | also needs `--allow-server-admin`, and is not available over MCP |
| local-only | the server accepts it only on its Unix socket and answers 403 over the network |

| Method | rexctl CLI | MCP tool | Class / note |
| --- | --- | --- | --- |
| `block.close` | `kill` | rex_kill | guarded |
| `block.event` | `input key`, `input paste`, `input focus`, `input mouse`, `input wheel`, `input event` | rex_op (guarded) | guarded |
| `block.method` | none | none | excluded, see below |
| `block_creator.list` | `admin block-creators` | rex_server_info | read |
| `client.action` | `admin client-action` | none (admin) | two flags |
| `client.inspect` | `admin client-inspect` | rex_server_info | read |
| `client.key` | `input key --via client-key` | rex_op (guarded) | guarded |
| `client.keymap` | `admin keymap` | rex_server_info | read |
| `client.list` | `admin client-list` | rex_server_info | read |
| `client.perform` | `admin client-perform` | none (admin) | two flags |
| `client.reply` | none | none | excluded, see below |
| `client.set_label` | `admin client-set-label` | none (admin) | two flags |
| `client.set_script` | none | none | excluded, see below |
| `data.connect` | `stream`, `wait-for --text/--idle` | rex_wait_for (text/idle) | read |
| `help.all` | `admin help-all` | rex_server_info | read |
| `hosts.list` | `admin hosts-list` | rex_server_info | read |
| `hosts.put` | `admin hosts-put` | none (admin) | two flags |
| `hosts.remove` | `admin hosts-remove` | none (admin) | two flags |
| `server.apple.grant_file_access` | none | none | excluded, see below |
| `server.apple.privacy_status` | `admin privacy-status` | none (admin) | read, local-only (403 over the network) |
| `server.config_reload` | `admin server-config-reload` | none (admin) | two flags, local-only (403 over the network) |
| `server.status` | `admin server-status` | rex_server_info | read |
| `server.stop` | `admin server-stop` | none (admin) | two flags, local-only (403 over the network) |
| `server.tailscale.disable` | `admin tailscale-disable` | none (admin) | two flags, local-only (403 over the network) |
| `server.tailscale.enable` | `admin tailscale-enable` | none (admin) | two flags, local-only (403 over the network) |
| `server.tailscale.login` | `admin tailscale-login` | none (admin) | two flags, local-only (403 over the network) |
| `server.tailscale.logout` | `admin tailscale-logout` | none (admin) | two flags, local-only (403 over the network) |
| `server.tailscale.rename` | `admin tailscale-rename` | none (admin) | two flags, local-only (403 over the network) |
| `server.version` | `version`, `hosts --check` | rex_hosts (check) | read |
| `server.whoami` | `version`, `hosts --check` | rex_hosts (check) | read |
| `session.attach` | `stream`, `wait-for --text/--idle`, `conn attach` | rex_op, rex_wait_for (text/idle) | read |
| `session.attach_all` | every command (event scope), `events` | rex_events_since | read |
| `session.bootstrap` | `conn bootstrap` | rex_op | read |
| `session.close_layer` | `layout close-layer` | rex_op (guarded) | guarded |
| `session.close_window` | `layout close-window` | rex_op (guarded) | guarded |
| `session.create` | `new-session` | rex_new_session | guarded |
| `session.describe_block` | `conn describe-block` | rex_op | read |
| `session.destroy` | `kill --whole-session` | rex_kill (whole_session) | guarded |
| `session.detach` | `stream` (end), `conn detach` | rex_op, rex_wait_for (text/idle) | read |
| `session.detach_block` | `conn detach-block` | rex_op (guarded) | guarded |
| `session.disown_block` | `conn disown-block` | rex_op (guarded) | guarded |
| `session.float_block` | `layout float-block` | rex_op (guarded) | guarded |
| `session.focus_block` | `layout focus-block` | rex_op (guarded) | guarded |
| `session.focus_direction` | `layout focus-direction` | rex_op (guarded) | guarded |
| `session.focus_next_pane` | `layout focus-next-pane` | rex_op (guarded) | guarded |
| `session.focus_next_window` | `layout focus-next-window` | rex_op (guarded) | guarded |
| `session.focus_previous_pane` | `layout focus-previous-pane` | rex_op (guarded) | guarded |
| `session.focus_previous_window` | `layout focus-previous-window` | rex_op (guarded) | guarded |
| `session.focus_window` | `layout focus-window` | rex_op (guarded) | guarded |
| `session.help` | `conn session-help` | rex_op | read |
| `session.list` | session names in `events -s` and in op flags that take a session | rex_events_since, rex_op | read |
| `session.list_blocks` | `wait-for --closed --no-stream`, `conn list-blocks` | rex_op, rex_wait_for | read |
| `session.list_clients` | `conn list-clients` | rex_op | read |
| `session.lower_layer` | `layout lower-layer` | rex_op (guarded) | guarded |
| `session.move` | `layout move-session` | rex_op (guarded) | guarded |
| `session.move_block` | `layout move-block` | rex_op (guarded) | guarded |
| `session.move_window` | `layout move-window` | rex_op (guarded) | guarded |
| `session.new_block` | `layout new-block` | rex_op (guarded) | guarded |
| `session.new_layer` | `layout new-layer` | rex_op (guarded) | guarded |
| `session.new_split` | `split` | rex_split | guarded |
| `session.new_window` | `layout new-window` | rex_op (guarded) | guarded |
| `session.own_block` | `conn own-block` | rex_op (guarded) | guarded |
| `session.raise_layer` | `layout raise-layer` | rex_op (guarded) | guarded |
| `session.resize_layer` | `layout resize-layer` | rex_op (guarded) | guarded |
| `session.resize_pane` | `layout resize-pane` | rex_op (guarded) | guarded |
| `session.set_block_label` | `layout set-block-label` | rex_op (guarded) | guarded |
| `session.set_label` | `layout set-session-label` | rex_op (guarded) | guarded |
| `session.set_window_label` | `layout set-window-label` | rex_op (guarded) | guarded |
| `session.swap_blocks` | `layout swap-blocks` | rex_op (guarded) | guarded |
| `session.view` | `ls`, target resolution | rex_ls, every tool with a target | read |
| `session.zoom_block` | `layout zoom-block` | rex_op (guarded) | guarded |
| `target.complete` | `target complete` | rex_op | read |
| `target.resolve` | `target resolve` | rex_op | read |
| `com.superlogical.onboarding.set_step` | `onboarding set-step` | rex_op (guarded) | guarded |
| `com.superlogical.onboarding.state` | `onboarding state` | rex_op | read |
| `com.superlogical.terminal.blob_read` | `term blob-read`, `tail` paging | rex_op, rex_tail | read (data redacted unless `--show`; raw `api call` is guarded) |
| `com.superlogical.terminal.clear` | `term clear` | rex_op (guarded) | guarded |
| `com.superlogical.terminal.clipboard_read` | `term clipboard-read` | rex_op | read |
| `com.superlogical.terminal.format` | `screen`, `tail`, `wait-for --text` | rex_screen, rex_tail, rex_wait_for | read |
| `com.superlogical.terminal.input_mode` | `term input-mode` | rex_op | read |
| `com.superlogical.terminal.list_dir` | `term list-dir` | rex_op | read |
| `com.superlogical.terminal.modes` | `term modes` | rex_op | read |
| `com.superlogical.terminal.process` | `process`, `ls` | rex_ls, rex_status | read |
| `com.superlogical.terminal.program_status` | `status`, `ls`, `wait-for --status` | rex_ls, rex_status, rex_wait_for | read |
| `com.superlogical.terminal.pwd` | `pwd`, `ls` | rex_ls, rex_status | read |
| `com.superlogical.terminal.reset` | `term reset` | rex_op (guarded) | guarded |
| `com.superlogical.terminal.resize` | `term resize` | rex_op (guarded) | guarded |
| `com.superlogical.terminal.set_theme` | `term set-theme` | rex_op (guarded) | guarded |
| `com.superlogical.terminal.size` | `term size` | rex_op | read |
| `com.superlogical.terminal.title` | `title`, `ls`, block title matching | rex_ls, rex_status | read |
| `com.superlogical.terminal.write` | `send` (text and `--keys`) | rex_send | guarded |

## Deliberate exclusions

- `block.method`: generic dispatcher; rexctl calls block methods by their full `<creator>.<method>` name (same server path). Raw: `api call block.method`.
- `client.reply`: answers `client_call_requested`/`client_perform_requested` for actions a client declares; rexctl declares none (no Lua/actions). Raw only.
- `client.set_script`: loads Lua scripts into this client; Lua is out of scope. Raw only (guarded).
- `server.apple.grant_file_access`: server-local (Unix socket only, 403 over the network) and needs macOS sandbox tokens from an app. Raw only.

## Not part of this table

- Events are not methods. `events`, the event conditions of `wait-for` and MCP `rex_events_since` consume the block
  events (`bell`, `child_exited`, `clipboard_written`, `desktop_notification`, `process_changed`,
  `program_status_changed`, `program_status_removed`, `progress_report`, `pwd_changed`, `selection_copied`,
  `size_changed`, `title_changed`, `url_clicked`) and the session and client events listed in [PROTOCOL.md](PROTOCOL.md).
- Out of scope: Lua, `rex do`, remote control of the GUI app, and the QUIC transport.
- MCP has no raw `api call`, no `stream` tool (`rex_wait_for` and `rex_events_since` cover waiting and watching) and no
  changing admin verbs.
