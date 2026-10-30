# Security

## What the guards are for

rexctl refuses to change anything until you pass `--yes-i-am-authorised`, and over MCP until the agent sends back the
`plan_id` of a dry run. This is an interlock. It stops an agent or a script from typing into the wrong terminal by
accident, and it makes a human look at the exact target before anything happens. It is not a security boundary.

Anyone who can run rexctl as you can also run `rexctl send ... --yes-i-am-authorised`, open a WebSocket to the server
directly, or use the official Rex CLI. The real access control is the Rex server: it decides who you are from the
connection, and it decides what that identity may do. If an agent must not touch a server, do not give it a network
path to that server.

The `plan_id` proves that the plan did not change between the dry run and the real run. It does not prove that a
human saw it: an agent can read the id from the dry run and pass it back itself, and `--yes-i-am-authorised` without
an id still works on the command line. If you need a human in the loop for every change, let your MCP client ask for
approval before each tool call.

`--allow-server-admin` works the same way. It makes server administration harder to trigger by mistake. It does not
make it impossible.

## Terminal text is untrusted

Whatever runs in a terminal controls what that terminal shows. A program can print text that looks like instructions
for an AI agent, set a misleading window title, or fake a prompt. rexctl therefore:

- matches block titles only exactly, so a program cannot capture a target name by setting a title that contains it;
- marks every MCP read result with an `untrusted` note;
- never runs anything it reads from a terminal;
- applies `--where` filters only after clipboard text is redacted, so a filter cannot be used to guess it;
- over MCP, accepts only host labels from the hosts file and refuses `@file` values, so text in a terminal cannot
  point the server at another host or make it read local files.

An agent that reads screens should treat their contents as data. It should never follow instructions found there.

## Secrets

- Keys whose names look like tokens, tickets, passwords or secrets are masked in all output.
- Clipboard text in events and in `term clipboard-read` and `term blob-read` is redacted unless you pass `--show`.
- `send --secret-file FILE` types a file's contents while the dry run shows only its length. The plan id does not depend on the contents either.
- The daemon keeps reconnect tokens in memory and never returns them to clients. Its socket lives in a directory that
  must be owned by you and closed to everyone else, and it checks the peer's uid on every connection. Clients ignore a
  socket whose directory or file others could have created, and connect directly instead.

None of this protects a secret once it has been typed into a terminal: it is then on the screen and in the scrollback,
where anyone who can read the block can read it.

## Reporting a problem

Report vulnerabilities privately through GitHub's "Report a vulnerability" button on the repository's Security tab.
Please do not open a public issue for them. Include the rexctl version or commit, the Rex server version from
`rexctl version`, and the smallest set of steps that shows the problem.

Problems in the Rex server itself belong to the Rex authors, not to this project.
