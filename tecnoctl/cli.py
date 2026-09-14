"""Command-line interface for :class:`tecnoctl.AlarmClient`."""

import argparse
import getpass
import json
import os

from dotenv import load_dotenv

from .client import AlarmClient, ProtocolError


def _one_based(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= number <= 65536:
        raise argparse.ArgumentTypeError("must be between 1 and 65536")
    return number - 1


def _app_id(value):
    try:
        number = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be a decimal or 0x-prefixed integer"
        ) from exc
    if not 0 <= number <= 0xFFFF:
        raise argparse.ArgumentTypeError("must fit in 16 bits")
    return number


def _positive(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def _nonnegative(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("cannot be negative")
    return number


def _parser():
    parser = argparse.ArgumentParser(
        description="Control a Tecnoalarm panel over direct TCP"
    )
    parser.add_argument("host", help="panel hostname or IP address")
    parser.add_argument("--port", type=int, default=10001)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--app-id",
        type=_app_id,
        help="16-bit client ID (default: stable value derived from this machine)",
    )
    parser.add_argument(
        "--passphrase", help="network passphrase (prefer TECNOCTL_PASSPHRASE)"
    )
    parser.add_argument(
        "--code", help="4-6 digit user code (prefer TECNOCTL_CODE)"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("info", help="panel model, limits, session, and raw information")
    commands.add_parser("clock", help="raw panel clock record")
    commands.add_parser("status", help="complete panel/program/remote status")
    commands.add_parser("panel-status", help="decoded central-unit status and all flags")
    commands.add_parser("group-status", help="program and remote status without names")
    commands.add_parser("permissions", help="program and remote permissions for this code")
    commands.add_parser("programs", help="program IDs, names, permissions, and states")
    commands.add_parser("remotes", help="remote-control IDs, names, permissions, and states")
    zones = commands.add_parser("zones", help="zone IDs, names, and states")
    zones.add_argument("--start", type=_one_based, default=0, metavar="ZONE")
    zones.add_argument("--count", type=_positive)
    zones.add_argument("--filter", choices=("all", "open", "isolated"), default="all")
    code_names = commands.add_parser("code-names", help="code labels only; never PIN digits")
    code_names.add_argument("--start", type=_one_based, default=0, metavar="CODE")
    code_names.add_argument("--count", type=_positive)
    events = commands.add_parser("events", help="event log; use --limit 0 for all")
    events.add_argument("--limit", type=_nonnegative, default=50)
    commands.add_parser("sync", help="full configuration and status synchronization")
    open_zones = commands.add_parser("open-zones", help="open zones blocking a program")
    open_zones.add_argument("program", type=_one_based)
    arm = commands.add_parser("arm", help="arm a program")
    arm.add_argument("program", type=_one_based)
    arm.add_argument("--exclude-open", action="store_true")
    disarm = commands.add_parser("disarm", help="disarm a program")
    disarm.add_argument("program", type=_one_based)
    remote_on = commands.add_parser("remote-on", help="turn a remote control on")
    remote_on.add_argument("remote", type=_one_based)
    remote_off = commands.add_parser("remote-off", help="turn a remote control off")
    remote_off.add_argument("remote", type=_one_based)
    zone_status = commands.add_parser("zone-status", help="read one zone")
    zone_status.add_argument("zone", type=_one_based)
    isolate = commands.add_parser("isolate", help="isolate a zone (master code required)")
    isolate.add_argument("zone", type=_one_based)
    reintegrate = commands.add_parser(
        "reintegrate", help="reintegrate a zone (master code required)"
    )
    reintegrate.add_argument("zone", type=_one_based)
    return parser


def main():
    load_dotenv(".env")
    parser = _parser()
    args = parser.parse_args()
    passphrase = args.passphrase or os.getenv("TECNOCTL_PASSPHRASE")
    code = args.code or os.getenv("TECNOCTL_CODE")
    if passphrase is None:
        passphrase = getpass.getpass("Network passphrase: ")
    if code is None:
        code = getpass.getpass("Access code: ")

    try:
        with AlarmClient(
            args.host,
            passphrase,
            code,
            port=args.port,
            app_id=args.app_id,
            timeout=args.timeout,
        ) as alarm:
            if args.command == "info":
                result = alarm.panel_info()
            elif args.command == "clock":
                result = {"raw": alarm.clock.hex()}
            elif args.command == "status":
                result = alarm.status()
            elif args.command == "panel-status":
                result = alarm.panel_status()
            elif args.command == "group-status":
                result = alarm.group_status()
            elif args.command == "permissions":
                result = alarm.permissions()
            elif args.command == "programs":
                result = alarm.programs()
            elif args.command == "remotes":
                result = alarm.remotes()
            elif args.command == "zones":
                result = alarm.zones(args.start, args.count)
                if args.filter != "all":
                    result = [zone for zone in result if zone[args.filter]]
            elif args.command == "code-names":
                result = alarm.code_names(args.start, args.count)
            elif args.command == "events":
                result = alarm.events(args.limit)
            elif args.command == "sync":
                result = alarm.sync()
            elif args.command == "open-zones":
                result = {"zones": [zone + 1 for zone in alarm.open_zones(args.program)]}
            else:
                _run_action(alarm, args)
                return
            print(json.dumps(result, indent=2))
    except (OSError, ProtocolError, ValueError) as exc:
        parser.exit(1, f"error: {exc}\n")


def _run_action(alarm, args):
    if args.command == "arm":
        excluded = alarm.arm(args.program, args.exclude_open)
        suffix = (
            f"; excluded zones {', '.join(str(zone + 1) for zone in excluded)}"
            if excluded
            else ""
        )
        print(f"program {args.program + 1} armed{suffix}")
    elif args.command == "disarm":
        alarm.disarm(args.program)
        print(f"program {args.program + 1} disarmed")
    elif args.command in ("remote-on", "remote-off"):
        enabled = args.command == "remote-on"
        alarm.remote(args.remote, enabled)
        print(f"remote {args.remote + 1} {'on' if enabled else 'off'}")
    elif args.command == "zone-status":
        print(json.dumps(alarm.zone_status(args.zone), indent=2))
    else:
        isolated = args.command == "isolate"
        alarm.set_zone_isolation(args.zone, isolated)
        print(f"zone {args.zone + 1} {'isolated' if isolated else 'reintegrated'}")


if __name__ == "__main__":
    main()
