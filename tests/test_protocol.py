import unittest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.decrepit.ciphers.modes import CFB

from tecnoctl.client import (
    AlarmClient,
    MODEL_LIMITS,
    RDY,
    STX,
    _bridge_frame,
    _crc16,
    _parse_response,
    _stuff,
    _take_frame,
)


class ProtocolTest(unittest.TestCase):
    def test_offline_protocol_and_decoders(self):
        self.assertEqual(_crc16(b"123456789"), 0x4B37)
        for model, (programs, remotes, *_limits) in MODEL_LIMITS.items():
            length, remote_bytes, program_offset, program_slots = (
                AlarmClient._group_layout(model)
            )
            self.assertLessEqual(programs, program_slots)
            self.assertLessEqual(program_offset + programs, length)
            self.assertLessEqual(remotes, remote_bytes * 8)

        payload = b"A\x10B"
        response = _bridge_frame(RDY, 0x1234, 2305, 2, payload)
        wire = _stuff(response)
        decoded, consumed = _take_frame(bytearray(wire))
        self.assertEqual(consumed, len(wire))
        self.assertEqual(
            _parse_response(decoded, 0x1234, 2305, 2, len(payload)), payload
        )

        key, iv = b"0123456789abcdef", bytes(16)
        encrypted = Cipher(algorithms.AES(key), CFB(iv)).encryptor().update(wire)
        decrypted = Cipher(algorithms.AES(key), CFB(iv)).decryptor().update(encrypted)
        self.assertEqual(decrypted, wire)

        response_payload = b"\x10" + bytes(15)
        response_wire = _stuff(
            _bridge_frame(RDY, 7, 2318, payload=response_payload)
        )
        response_ciphertext = (
            Cipher(algorithms.AES(key), CFB(iv)).encryptor().update(response_wire)
        )

        class FakeSocket:
            def __init__(self):
                self.sent = b""
                self.chunks = [response_ciphertext[:5], response_ciphertext[5:]]

            def sendall(self, data):
                self.sent += data

            def recv(self, _size):
                return self.chunks.pop(0)

        transport = object.__new__(AlarmClient)
        transport.session, transport.rx = 7, bytearray()
        transport.sock = FakeSocket()
        transport.encryptor = Cipher(algorithms.AES(key), CFB(iv)).encryptor()
        transport.decryptor = Cipher(algorithms.AES(key), CFB(iv)).decryptor()
        self.assertEqual(
            transport._exchange(2318, expected_length=16), response_payload
        )
        request_wire = (
            Cipher(algorithms.AES(key), CFB(iv))
            .decryptor()
            .update(transport.sock.sent)
        )
        self.assertEqual(request_wire, _stuff(_bridge_frame(STX, 7, 2318)))

        panel = object.__new__(AlarmClient)
        panel._info = bytes((49, 0)) + bytes(14)
        panel._permissions = None
        panel.session, panel.app_id = 1, 0x1234
        calls = []

        def fake_exchange(record, index=0, payload=b"", expected_length=0):
            calls.append((record, index, bytes(payload), expected_length))
            return bytes(expected_length)

        panel._exchange = fake_exchange
        self.assertEqual(panel.profile()["max_zones"], 50)
        self.assertEqual(len(panel.group_status()["remotes"]), 32)
        self.assertEqual(calls[-1][0], 2340)
        panel._info = bytes((42, 5)) + bytes(14)
        self.assertEqual(panel._description("zone", 0), "Z1")
        self.assertEqual(panel.code_names(0, 1), [{"code": 1, "name": "Cod1"}])
        self.assertEqual(len(panel.zone_statuses(0, 2)), 2)
        self.assertEqual(len(panel.events(1)["events"]), 1)
        self.assertTrue(panel._decode_zone(2, b"\x03\x00\x00\x00")["open"])
        event = panel._decode_event(1, b"\x01\x00\x02\x00\x00\x00\x00\x00")
        self.assertEqual(event["timestamp"], "2000-01-01 00:00:00")
        operation = panel._operation_payload(3, 2, 1, (4, 5))
        self.assertEqual(operation[:8], b"\x03\x02\x00\x00\x01\x00\x0e\x20")
        self.assertEqual(operation[10:14], b"\x04\x00\x05\x00")


if __name__ == "__main__":
    unittest.main()
