"""Reusable client for the myTecnoalarm direct encrypted-TCP protocol."""

from datetime import datetime, timedelta
import secrets
import socket
import struct
import time
import uuid

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.decrepit.ciphers.modes import CFB


DLE, STX, ACK, RDY, NAK, BUSY = 0x10, 0x02, 0x06, 0x0C, 0x15, 0x0F
BRIDGE_RECORD = 2304
EVOLUTION_MODELS = {49, 50, 57, 58}
LONG_TEXT_MODELS = {35, 36, 38, 39, 42, 43, 44, 45, 46, 47, 48, 49, 50, 57, 58}
MODEL_NAMES = {
    33: "TP888", 34: "TP888E", 35: "TP440", 36: "TP440E",
    38: "TP42", 39: "TP42E", 42: "EV424", 43: "EV424E",
    45: "TP888P", 46: "TP888PE", 47: "TP312", 48: "TP312E",
    49: "EV50", 50: "EV50E", 57: "EV150", 58: "EV150E",
}
MODEL_LIMITS = {
    13: (32, 16, 256, 201, 2000),
    24: (32, 32, 512, 301, 2000),
    25: (8, 8, 96, 201, 2000),
    29: (8, 8, 28, 121, 1500), 30: (8, 8, 28, 121, 1500),
    31: (8, 8, 28, 121, 1500), 32: (8, 8, 28, 121, 1500),
    33: (8, 8, 88, 201, 1500), 34: (8, 8, 88, 201, 1500),
    35: (32, 32, 440, 301, 2000), 36: (32, 32, 440, 301, 2000),
    38: (8, 8, 42, 121, 1500), 39: (8, 8, 42, 121, 1500),
    40: (8, 8, 28, 121, 1500), 41: (8, 8, 28, 121, 1500),
    42: (6, 6, 24, 49, 2000), 43: (6, 6, 24, 49, 2000),
    44: (32, 32, 440, 301, 2000),
    45: (16, 16, 88, 201, 1500), 46: (16, 16, 88, 201, 1500),
    47: (32, 32, 312, 301, 2000), 48: (32, 32, 312, 301, 2000),
    49: (8, 32, 50, 121, 2000), 50: (8, 32, 50, 121, 2000),
    57: (16, 32, 150, 201, 2000), 58: (16, 32, 150, 201, 2000),
}
RECORD_NAMES = {
    1: "clock", 2305: "authentication", 2306: "operation",
    2307: "program description", 2308: "remote description",
    2309: "code description", 2310: "zone description", 2311: "start event log",
    2312: "event log", 2313: "panel information", 2314: "permissions",
    2316: "zone status", 2317: "program/remote status", 2318: "panel status",
    2319: "priority", 2320: "isolate zone", 2321: "reintegrate zone",
    2339: "Evolution remote description", 2340: "Evolution program/remote status",
}
GENERAL_STATUS_BITS = (
    ("standby", "fault", "battery_alarm", "power_alarm", "tamper_active", "anomaly_active", "robbery_active", "technical_active"),
    ("chime", "line_status", "prealarm", "program_alarm", "access_denied", "alarm", "system_ok", "cellular_status"),
    ("tamper_alarm", "anomaly_alarm", "false_code_alarm", "false_key_alarm", "alive_alarm", "mask_alarm", "robbery_alarm", "technical_alarm"),
    ("generic_memory", "exit_time", "maintenance", "call_active", "partial_warning", "automatic_warning", "zones_isolated", "mask_active"),
    ("tamper_memory", "anomaly_memory", "false_code_memory", "false_key_memory", "call_memory", "battery_memory", "power_memory", "line_memory"),
    ("cellular_memory", "voice_memory_expired", "answerer_on", "internal_siren", "external_siren", "output_1", "output_2", "local_expansion"),
    ("panic", "failure_alarm", "failure_active", "mask_key_active", "output_3", "output_4", "isolation_inhibited", "failure_memory"),
    ("tecno_output_internal_siren", "tecno_output_external_siren", "tecno_output_1", "tecno_output_2", "tecno_output_3", "tecno_output_4", "reserved_6", "reserved_7"),
)


class ProtocolError(RuntimeError):
    pass


def _crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc


def _bridge_frame(control, session, record, index=0, payload=b""):
    body = struct.pack(
        "<HHHHHH", BRIDGE_RECORD, session, len(payload) + 6, record, index, len(payload)
    ) + payload
    return bytes((DLE, control)) + body + struct.pack("<H", _crc16(body))


def _stuff(frame):
    return frame[:2] + frame[2:].replace(b"\x10", b"\x10\x10")


def _take_frame(buffer):
    """Return (unescaped frame, consumed bytes), or None for incomplete input."""
    if len(buffer) < 2:
        return None
    if buffer[0] != DLE:
        raise ProtocolError(f"invalid response prefix 0x{buffer[0]:02x}")

    offset = 0
    if buffer[1] == BUSY:
        if len(buffer) < 4:
            return None
        if buffer[2] != DLE:
            raise ProtocolError("invalid BUSY response")
        offset = 2

    control = buffer[offset + 1]
    if control in (ACK, NAK):
        return bytes(buffer[: offset + 2]), offset + 2
    if control != RDY:
        raise ProtocolError(f"unexpected control byte 0x{control:02x}")

    decoded = bytearray(buffer[: offset + 2])
    cursor = offset + 2
    wanted = None
    while cursor < len(buffer):
        byte = buffer[cursor]
        decoded.append(byte)
        cursor += 1
        if byte == DLE:
            if cursor == len(buffer):
                return None
            if buffer[cursor] != DLE:
                raise ProtocolError("invalid DLE escaping")
            cursor += 1

        if wanted is None and len(decoded) >= offset + 14:
            payload_length = int.from_bytes(decoded[offset + 12 : offset + 14], "little")
            if payload_length > 4096:
                raise ProtocolError(f"implausible payload length {payload_length}")
            wanted = offset + payload_length + 16
        if wanted is not None and len(decoded) == wanted:
            return bytes(decoded), cursor
        if wanted is not None and len(decoded) > wanted:
            raise ProtocolError("response exceeded declared length")
    return None


def _parse_response(frame, session, record, index, expected_length):
    offset = 2 if frame[1] == BUSY else 0
    control = frame[offset + 1]
    if control == NAK:
        raise ProtocolError("alarm rejected the request (NAK)")
    if control == ACK:
        if expected_length:
            raise ProtocolError("alarm returned ACK without the expected data")
        return b""
    if control != RDY:
        raise ProtocolError(f"unexpected response control 0x{control:02x}")

    outer, response_session, inner_length, response_record, response_index, payload_length = (
        struct.unpack_from("<HHHHHH", frame, offset + 2)
    )
    if outer != BRIDGE_RECORD:
        raise ProtocolError(f"unexpected bridge record {outer}")
    if response_session != session:
        raise ProtocolError(f"session mismatch: expected {session}, got {response_session}")
    if inner_length != payload_length + 6:
        raise ProtocolError("invalid inner length")
    if response_record != record or response_index != index:
        raise ProtocolError(
            f"response mismatch: record/index {response_record}/{response_index}"
        )
    if payload_length != expected_length:
        raise ProtocolError(
            f"unexpected payload length: expected {expected_length}, got {payload_length}"
        )

    body_start = offset + 2
    payload_start = offset + 14
    payload_end = payload_start + payload_length
    received_crc = int.from_bytes(frame[payload_end : payload_end + 2], "little")
    if received_crc != _crc16(frame[body_start:payload_end]):
        raise ProtocolError("response CRC mismatch")
    return frame[payload_start:payload_end]


class AlarmClient:
    """A direct TCP session with a Tecnoalarm panel.

    Program, remote, and zone arguments use zero-based indexes. Returned IDs
    are one-based for display.
    """

    def __init__(
        self, host, passphrase, code, *, port=10001, app_id=None, timeout=10.0
    ):
        if app_id is None:
            app_id = uuid.getnode() & 0xFFFF or 1
        if not host:
            raise ValueError("host is required")
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if not code.isdigit() or not 4 <= len(code) <= 6:
            raise ValueError("access code must contain 4 to 6 digits")
        if not passphrase:
            raise ValueError("passphrase is required")
        if not 0 <= app_id <= 0xFFFF:
            raise ValueError("app ID must fit in 16 bits")

        self.host, self.port, self.timeout = host, port, timeout
        self.key = bytes(ord(char) & 0xFF for char in passphrase[:16].ljust(16))
        self.code, self.app_id = code, app_id
        self.session = 0
        self.clock = b""
        self._info = None
        self._permissions = None
        self.sock = self.encryptor = self.decryptor = None
        self.rx = bytearray()

    def __enter__(self):
        return self.connect()

    def __exit__(self, *_):
        self.close()

    def connect(self):
        try:
            self.session = 0
            self.clock = b""
            self._info = self._permissions = None
            self.rx.clear()
            self.sock = socket.create_connection((self.host, self.port), self.timeout)
            self.sock.settimeout(self.timeout)
            iv = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(self.key), CFB(iv))
            self.encryptor, self.decryptor = cipher.encryptor(), cipher.decryptor()
            time.sleep(0.5)  # The official app gives the panel time to enter crypto mode.
            self.sock.sendall(iv)

            try:
                self.clock = self._exchange(1, expected_length=10)
            except (OSError, ProtocolError) as exc:
                raise ProtocolError(
                    "clock handshake (record 1) failed: "
                    f"{exc}; check the direct-TCP port and network passphrase"
                ) from exc
            auth = bytearray(48)
            auth[:2] = self.app_id.to_bytes(2, "little")
            auth[2 : 2 + len(self.code)] = bytes(map(int, self.code))
            auth[8] = 1
            try:
                response = self._exchange(2305, payload=auth, expected_length=3)
            except (OSError, ProtocolError) as exc:
                raise ProtocolError(
                    "authentication handshake (record 2305) failed: "
                    f"{exc}; check the access code, app ID, and user permissions"
                ) from exc
            if response[0] != ACK:
                raise ProtocolError(
                    "authentication handshake (record 2305) returned "
                    f"{response.hex()} instead of ACK; check the access code, app ID, "
                    "and user permissions"
                )
            self.session = int.from_bytes(response[1:3], "little")
            return self
        except Exception:
            self.close()
            raise

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def _exchange(self, record, index=0, payload=b"", expected_length=0):
        try:
            frame = _bridge_frame(STX, self.session, record, index, bytes(payload))
            self.sock.sendall(self.encryptor.update(_stuff(frame)))
            while True:
                complete = _take_frame(self.rx)
                if complete is not None:
                    response, consumed = complete
                    del self.rx[:consumed]
                    return _parse_response(
                        response, self.session, record, index, expected_length
                    )
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise ProtocolError("alarm closed the connection")
                self.rx.extend(self.decryptor.update(chunk))
        except (OSError, ProtocolError) as exc:
            name = RECORD_NAMES.get(record, "unknown")
            raise ProtocolError(
                f"{name} request (record {record}, index {index}) failed: {exc}"
            ) from exc

    def _panel_info_raw(self):
        if self._info is None:
            self._info = self._exchange(2313, expected_length=16)
        return self._info

    def profile(self):
        info = self._panel_info_raw()
        programs, remotes, zones, codes, events = MODEL_LIMITS.get(
            info[0], (8, 8, 28, 121, 1500)
        )
        return {
            "model_id": info[0],
            "model": MODEL_NAMES.get(info[0], f"model-{info[0]}"),
            "firmware_nature": info[1],
            "max_programs": programs,
            "max_remotes": remotes,
            "max_zones": zones,
            "max_code_names": codes,
            "event_capacity": events,
        }

    def panel_info(self):
        info = self._panel_info_raw()
        return {
            **self.profile(),
            "session": self.session,
            "master_session": self.session == 1,
            "app_id": self.app_id,
            "raw": info.hex(),
        }

    def panel_status(self):
        data = self._exchange(2318, expected_length=16)
        general = data[8:16]
        flags = {
            name: bool(general[byte] & (1 << bit))
            for byte, names in enumerate(GENERAL_STATUS_BITS)
            for bit, name in enumerate(names)
        }
        flags.update(
            battery=flags["battery_alarm"] or flags["battery_memory"],
            powerless=flags["power_alarm"] or flags["power_memory"],
            tamper=flags["tamper_active"] or flags["tamper_memory"],
            anomaly=flags["anomaly_active"] or flags["anomaly_memory"],
            false_code=flags["false_code_alarm"] or flags["false_code_memory"],
            false_key=flags["false_key_alarm"] or flags["false_key_memory"],
        )
        return {
            "firmware_nature": data[0],
            "firmware_release": data[1],
            "hardware_release": data[2],
            "vocabulary_nature": data[3],
            "vocabulary_release": data[4],
            "supply_voltage_raw": data[5],
            "battery_voltage_raw": data[6],
            "phone_call_active": bool(data[7] & 0x01),
            "answerer_active": bool(data[7] & 0x02),
            "secure_connection": bool(data[7] & 0x04),
            "general": flags,
            "raw": data.hex(),
        }

    @staticmethod
    def _group_layout(model):
        if model == 13:
            return 34, 2, 2, 32
        if model in (24, 35, 36, 44, 47, 48):
            return 36, 4, 4, 32
        if model in (57, 58):
            return 64, 4, 32, 16
        if model in (45, 46):
            return 20, 4, 4, 16
        if model in (49, 50):
            return 64, 4, 32, 8
        if model in (42, 43):
            return 12, 2, 4, 6
        return 12, 4, 4, 8

    def group_status(self):
        profile = self.profile()
        length, remote_bytes, program_offset, program_count = self._group_layout(
            profile["model_id"]
        )
        record = 2340 if profile["model_id"] in EVOLUTION_MODELS else 2317
        data = self._exchange(record, expected_length=length)
        remote_bits = int.from_bytes(data[:remote_bytes], "little")
        return {
            "programs": [
                {
                    "program": i + 1,
                    "state": data[program_offset + i] & 0x0F,
                    "state_group": (
                        "disarmed" if (data[program_offset + i] & 0x0F) == 0
                        else "partial" if (data[program_offset + i] & 0x0F) in (4, 5)
                        else "armed-or-transition"
                    ),
                    "armed": (data[program_offset + i] & 0x0F) != 0,
                    "flags": data[program_offset + i] & 0xF0,
                }
                for i in range(min(program_count, profile["max_programs"]))
            ],
            "remotes": [
                {"remote": i + 1, "on": bool(remote_bits & (1 << i))}
                for i in range(profile["max_remotes"])
            ],
            "raw": data.hex(),
        }

    def permissions(self):
        if self._permissions is not None:
            return self._permissions
        model = self.profile()["model_id"]
        length = 12 if model in (35, 36, 47, 48) else 8
        data = self._exchange(2314, index=self.session, expected_length=length)
        program_mask = int.from_bytes(data[:4], "little")
        remote_flag_offset = (4 if model in (35, 36, 47, 48, 57, 58) else 0) + 6
        self._permissions = {
            "program_mask": program_mask,
            "programs": [
                i + 1
                for i in range(self.profile()["max_programs"])
                if program_mask & (1 << i)
            ],
            "remote_access": (
                not bool(data[remote_flag_offset] & 0x02)
                if remote_flag_offset < len(data)
                else None
            ),
            "raw": data.hex(),
        }
        return self._permissions

    def _description(self, kind, index):
        if kind not in ("program", "remote", "zone", "code"):
            raise ValueError(f"unknown description type {kind!r}")
        profile = self.profile()
        model = profile["model_id"]
        maximum = profile["max_code_names" if kind == "code" else f"max_{kind}s"]
        if not 0 <= index < maximum:
            raise ValueError(f"{kind} must be between 1 and {maximum}")

        if kind == "program":
            record, length, fallback = 2307, (32 if model in LONG_TEXT_MODELS else 24), f"P{index + 1}"
        elif kind == "remote":
            record = 2339 if model in EVOLUTION_MODELS else 2308
            length = 38 if model in EVOLUTION_MODELS else (34 if model in LONG_TEXT_MODELS else 26)
            fallback = f"T{index + 1}"
        elif kind == "zone":
            record, length, fallback = 2310, (32 if model in LONG_TEXT_MODELS else 24), f"Z{index + 1}"
        else:
            record, length, fallback = 2309, (24 if model in LONG_TEXT_MODELS else 16), f"Cod{index + 1}"

        raw = self._exchange(record, index=index, expected_length=length)
        encoded = raw[:16].split(b"\0", 1)[0]
        encoding = "iso-8859-7" if profile["firmware_nature"] == 5 else "utf-8"
        return encoded.decode(encoding, "replace").rstrip() or fallback

    def descriptions(self, kind, start=0, count=None):
        if kind not in ("program", "remote", "zone", "code"):
            raise ValueError(f"unknown description type {kind!r}")
        profile = self.profile()
        maximum = profile["max_code_names" if kind == "code" else f"max_{kind}s"]
        start, count = self._range(kind, start, count, maximum)
        return [
            {kind: i + 1, "name": self._description(kind, i)}
            for i in range(start, start + count)
        ]

    @staticmethod
    def _range(kind, start, count, maximum):
        if not 0 <= start < maximum:
            raise ValueError(f"first {kind} must be between 1 and {maximum}")
        if count is None:
            count = maximum - start
        if count < 1 or start + count > maximum:
            raise ValueError(f"{kind} range exceeds 1..{maximum}")
        return start, count

    def programs(self):
        states = self.group_status()["programs"]
        enabled = set(self.permissions()["programs"])
        for item in states:
            item["name"] = self._description("program", item["program"] - 1)
            item["enabled"] = item["program"] in enabled
        return states

    def remotes(self):
        states = self.group_status()["remotes"]
        access = self.permissions()["remote_access"]
        for item in states:
            item["name"] = self._description("remote", item["remote"] - 1)
            item["enabled"] = access
        return states

    @staticmethod
    def _decode_zone(zone, data):
        return {
            "zone": zone + 1,
            "open": bool(data[0] & 0x02 or data[3] & 0x02),
            "isolated": bool(data[0] & 0x01),
            "raw": data.hex(),
        }

    def zone_statuses(self, start=0, count=None):
        maximum = self.profile()["max_zones"]
        start, count = self._range("zone", start, count, maximum)
        result = []
        while count:
            batch = min(count, 25)
            raw = self._exchange(
                2316, index=start, payload=struct.pack("<H", batch),
                expected_length=batch * 4,
            )
            result.extend(
                self._decode_zone(start + i, raw[i * 4 : i * 4 + 4])
                for i in range(batch)
            )
            start += batch
            count -= batch
        return result

    def zone_status(self, zone):
        return self.zone_statuses(zone, 1)[0]

    def zones(self, start=0, count=None):
        result = self.zone_statuses(start, count)
        for item in result:
            item["name"] = self._description("zone", item["zone"] - 1)
        return result

    def code_names(self, start=0, count=None):
        return self.descriptions("code", start, count)

    def sync(self):
        return {
            "panel": self.panel_info(),
            "permissions": self.permissions(),
            "programs": self.programs(),
            "remotes": self.remotes(),
            "zones": self.zones(),
            "code_names": self.code_names(),
        }

    def events(self, limit=50):
        if limit < 0:
            raise ValueError("event limit cannot be negative")
        capacity = self.profile()["event_capacity"]
        wanted = capacity if limit == 0 else min(limit, capacity)
        start_index = int.from_bytes(self._exchange(2311, expected_length=2), "little")
        result = []
        finished = False
        while len(result) < wanted and not finished:
            batch = min(12, wanted - len(result))
            raw = self._exchange(
                2312, index=len(result) + 1, payload=struct.pack("<H", batch),
                expected_length=batch * 8,
            )
            for i in range(batch):
                event = raw[i * 8 : i * 8 + 8]
                if event[:4] == b"\xff\xff\xff\xff":
                    finished = True
                    break
                result.append(self._decode_event(len(result) + 1, event))
        return {"start_index": start_index, "events": result}

    @staticmethod
    def _decode_event(index, data):
        seconds = int.from_bytes(data[4:8], "little")
        timestamp = datetime(2000, 1, 1) + timedelta(seconds=seconds)
        return {
            "index": index,
            "timestamp": timestamp.isoformat(sep=" "),
            "event": data[0] | ((data[1] << 8) & 0x300),
            "argument": data[2] | ((data[3] << 8) & 0x300),
            "detail_1": (data[1] >> 2) & 0x3F,
            "detail_2": (data[3] >> 2) & 0x3F,
            "raw": data.hex(),
        }

    def status(self):
        return {
            "panel": self.panel_info(),
            "clock_raw": self.clock.hex(),
            "status": self.panel_status(),
            **self.group_status(),
        }

    @staticmethod
    def _operation_payload(action, target, session, open_zones=()):
        if not 0 <= target <= 0xFF:
            raise ValueError("program/remote number is out of range")
        if len(open_zones) > 25:
            raise ProtocolError("the panel reported more than 25 open zones")
        payload = bytearray(60)
        payload[0], payload[1] = action, target
        payload[4:6] = session.to_bytes(2, "little")
        payload[6], payload[7] = 14, 32
        for position, zone in enumerate(open_zones):
            struct.pack_into("<H", payload, 10 + position * 2, zone)
        return payload

    def _operation(self, action, target, open_zones=()):
        payload = self._operation_payload(action, target, self.session, open_zones)
        response = self._exchange(2306, payload=payload, expected_length=1)
        if response != bytes((ACK,)):
            raise ProtocolError(f"operation failed: {response.hex()}")

    def _priority(self):
        self._exchange(2319, payload=b"\x01\x00\x00\x00")

    def _check_target(self, kind, target):
        maximum = self.profile()[f"max_{kind}s"]
        if not 0 <= target < maximum:
            raise ValueError(f"{kind} must be between 1 and {maximum}")

    def open_zones(self, program):
        self._check_target("program", program)
        payload = self._operation_payload(24, program, self.session)
        response = self._exchange(2306, payload=payload, expected_length=104)
        if response[0] != ACK:
            raise ProtocolError(f"open-zone query failed: {response.hex()}")
        count = int.from_bytes(response[2:4], "little")
        if count > 50:
            raise ProtocolError(f"invalid open-zone count {count}")
        return [int.from_bytes(response[4 + i * 2 : 6 + i * 2], "little") for i in range(count)]

    def arm(self, program, exclude_open=False):
        self._check_target("program", program)
        if program + 1 not in self.permissions()["programs"]:
            raise ProtocolError(f"access code cannot control program {program + 1}")
        if self.panel_status()["general"]["maintenance"]:
            raise ProtocolError("the panel is in maintenance mode")
        zones = self.open_zones(program)
        if zones and not exclude_open:
            shown = ", ".join(str(zone + 1) for zone in zones)
            raise ProtocolError(
                f"program has open zones ({shown}); close them or rerun with --exclude-open"
            )
        if len(zones) > 25:
            raise ProtocolError("cannot exclude more than 25 open zones")
        self._priority()
        self._operation(3, program, zones)
        return zones

    def disarm(self, program):
        self._check_target("program", program)
        if program + 1 not in self.permissions()["programs"]:
            raise ProtocolError(f"access code cannot control program {program + 1}")
        self._priority()
        self._operation(4, program)

    def remote(self, remote, turn_on):
        self._check_target("remote", remote)
        if self.permissions()["remote_access"] is False:
            raise ProtocolError("access code cannot control remotes")
        self._priority()
        self._operation(11 if turn_on else 12, remote)

    def set_zone_isolation(self, zone, isolated):
        self._check_target("zone", zone)
        if self.session != 1:
            raise ProtocolError("zone isolation requires a master access code")
        self._priority()
        response = self._exchange(2320 if isolated else 2321, index=zone, expected_length=1)
        if response != bytes((ACK,)):
            raise ProtocolError(f"zone operation failed: {response.hex()}")
