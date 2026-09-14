# tecnoctl

Unofficial Python client and CLI for the direct TCP interface used by the
myTecnoalarm Android application. It does not use Tecnoalarm cloud, HTTP, or
video services.

> Experimental: This project was developed with AI assistance. The protocol was reverse-engineered and has not been tested on
> every hardware. Start with read-only commands. The protocol uses unauthenticated
> AES-CFB; never expose TCP port 10001 to the Internet. Use a trusted LAN or VPN.

## Install

```sh
pip install tecnoctl
```

## CLI

```sh
cp .env.example .env
# Edit .env with your credentials.

tecnoctl HOST status
tecnoctl HOST --verbose status
tecnoctl HOST --debug status
tecnoctl HOST zones
tecnoctl HOST watch
tecnoctl HOST arm 1
tecnoctl HOST disarm 1
```

The CLI loads `.env` automatically; exported variables take precedence. Run
`tecnoctl --help` for all commands. CLI IDs are one-based. `watch` connects,
checks, and disconnects every 30 seconds, then prints JSON when an alarm starts,
a program starts arming or becomes armed/disarmed, or connectivity changes. The
minimum `--interval` is 5 seconds. Add `--debug` before any command for
connection and protocol diagnostics, or `--verbose` for quieter connection
status. 

> `watch` is experimental and is not a primary alarm notification system. Some
> panels accept only one direct TCP client, so each check may briefly delay the
> official app.

## Python API

```python
from tecnoctl import AlarmClient

with AlarmClient("192.168.1.20", "network passphrase", "123456") as alarm:
    print(alarm.status())
    alarm.arm(0)  # Library indexes are zero-based.
```

The class also exposes panel, program, remote, zone, permission, and event-log
queries. `alarm.watch()` yields JSON-friendly alarm and connection events. See
`AlarmClient` in `tecnoctl/client.py`.

## Development

```sh
python3 -m unittest discover -s tests
```

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

MIT licensed. Tecnoalarm is a trademark of its owner; this project is not
affiliated with or endorsed by Tecnoalarm.
