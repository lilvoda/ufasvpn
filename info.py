import time
import random
import socket
import struct
import zlib
import threading
import re

import zstandard as zstd
from Crypto.Cipher import AES
from enum import Enum
from typing import Any, Tuple, Optional, Dict, List
from collections import defaultdict

DEVICE_MODELS = [
    'Xiaomi:23049PCD8G', 'Xiaomi:2201123G', 'Xiaomi:22011211C', 'Xiaomi:2211133C',
    'Xiaomi:23078PND5G', 'Xiaomi:22101316G', 'Xiaomi:Redmi Note 12', 'Xiaomi:Redmi Note 12 Pro',
    'Xiaomi:Redmi Note 11', 'Xiaomi:Redmi 12C', 'Xiaomi:Redmi 10', 'Xiaomi:Mi 11',
    'Xiaomi:Mi 11 Ultra', 'Xiaomi:23013RK75G', 'Xiaomi:2304FPN6DG', 'Xiaomi:23054RA19I',
    'Xiaomi:22071219CG', 'Xiaomi:2206123SC', 'Xiaomi:220733SG', 'Xiaomi:22041219NY',
    'Xiaomi:2203121C', 'Xiaomi:2201116SG', 'Xiaomi:220333QNY', 'Xiaomi:22101316C',
    'Xiaomi:2210132C', 'Xiaomi:220733SPG', 'Xiaomi:2211133G', 'Xiaomi:2304FPN6DC',
    'Xiaomi:23090RA98C', 'Xiaomi:23106RN0DA', 'Xiaomi:2312DRA50C', 'Xiaomi:2201123C',
    'Xiaomi:2211101C', 'Xiaomi:2304FPN6DI', 'Xiaomi:2207117BPG', 'Xiaomi:2112123AC',
    'Xiaomi:22120RN86G', 'Xiaomi:2206122SC', 'Xiaomi:22041216I', 'Xiaomi:2207117BPI',
    'Xiaomi:Redmi Note 13', 'Xiaomi:Redmi Note 13 Pro', 'Xiaomi:Redmi 13C', 'Xiaomi:Redmi A3',
    'Xiaomi:POCO X6', 'Xiaomi:POCO M6', 'Xiaomi:POCO C65', 'Xiaomi:POCO F6',
    'Xiaomi:Mi 14', 'Xiaomi:Mi 14 Ultra',
]

AES_KEY = bytes.fromhex('f5a193d50ade553e9835595f5cd75ddd')
AES_IV = b'\x00' * 16


class SdpDataType(Enum):
    INTEGER_POSITIVE = 0
    INTEGER_NEGATIVE = 1
    FLOAT = 2
    DOUBLE = 3
    STRING = 4
    LIST = 5
    DICT = 6
    STRUCT_BEGIN = 7
    STRUCT_END = 8


class SdpException(Exception):
    pass


class SdpStruct(dict):
    def __init__(self, data=None, _pack: bool = True):
        super().__init__()
        self.data = b''
        self.offset = 0

        if isinstance(data, bytes):
            self.data = data
            self.offset = 0
            self._unpack_from_binary()
        elif data is not None:
            super().update(data)
            if _pack:
                self._pack_to_binary()

    def _pack_to_binary(self):
        self.data = bytes([SdpDataType.STRUCT_BEGIN.value << 4])
        for tag, value in sorted(self.items(), key=lambda kv: (kv[0] if isinstance(kv[0], int) else 0, str(kv[0]))):
            self._pack(tag, value)
        self.data += bytes([SdpDataType.STRUCT_END.value << 4])

    def _write_number(self, value: int) -> bytes:
        result = bytearray()
        while value >= 0x80:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    def _pack_header(self, tag: int, data_type: SdpDataType) -> None:
        if tag < 15:
            self.data += bytes([(data_type.value << 4) | tag])
        else:
            self.data += bytes([(data_type.value << 4) | 15])
            self.data += self._write_number(tag)

    def _pack(self, tag: int, value: Any) -> None:
        if isinstance(value, bool):
            self._pack_header(tag, SdpDataType.INTEGER_POSITIVE)
            self.data += self._write_number(1 if value else 0)
        elif isinstance(value, int):
            if value < 0:
                self._pack_header(tag, SdpDataType.INTEGER_NEGATIVE)
                self.data += self._write_number(-value)
            else:
                self._pack_header(tag, SdpDataType.INTEGER_POSITIVE)
                self.data += self._write_number(value)
        elif isinstance(value, float):
            self._pack_header(tag, SdpDataType.DOUBLE)
            packed = struct.pack("<d", value)
            self.data += self._write_number(len(packed))
            self.data += packed
        elif isinstance(value, (str, bytes)):
            self._pack_header(tag, SdpDataType.STRING)
            encoded = value.encode('utf-8') if isinstance(value, str) else value
            self.data += self._write_number(len(encoded))
            self.data += encoded
        elif isinstance(value, list):
            self._pack_header(tag, SdpDataType.LIST)
            self.data += self._write_number(len(value))
            for item in value:
                self._pack(0, item)
        elif isinstance(value, dict):
            if isinstance(value, SdpStruct):
                self._pack_header(tag, SdpDataType.STRUCT_BEGIN)
                for k, v in sorted(value.items(), key=lambda kv: (kv[0] if isinstance(kv[0], int) else 0, str(kv[0]))):
                    self._pack(k, v)
                self.data += bytes([SdpDataType.STRUCT_END.value << 4])
            else:
                self._pack_header(tag, SdpDataType.DICT)
                self.data += self._write_number(len(value))
                for k, v in sorted(value.items(), key=lambda kv: str(kv[0])):
                    self._pack(0, k)
                    self._pack(0, v)
        else:
            raise SdpException(f"Unsupported type: {type(value)}")

    def _unpack_from_binary(self):
        if not self.data:
            return
        if self.data[0] >> 4 == SdpDataType.STRUCT_BEGIN.value:
            self.offset = 1
            if (self.data[0] & 0xF) == 15:
                self._read_number()
            while self.offset < len(self.data):
                tag, value = self._unpack()
                if isinstance(value, SdpDataType) and value == SdpDataType.STRUCT_END:
                    break
                self[tag] = value

    def _read_number(self) -> int:
        if self.offset >= len(self.data):
            raise SdpException("Unexpected EOF in varint")
        n = 1
        val = self.data[self.offset] & 0x7F
        while self.data[self.offset + n - 1] >= 0x80:
            if n > 10 or self.offset + n >= len(self.data):
                raise SdpException("Truncated or overflowed varint")
            val |= (self.data[self.offset + n] & 0x7F) << (7 * n)
            n += 1
        self.offset += n
        return val

    def _unpack(self) -> Tuple[int, Any]:
        if self.offset >= len(self.data):
            return 0, None

        header = self.data[self.offset]
        tag = header & 0xF
        try:
            data_type = SdpDataType(header >> 4)
        except ValueError:
            raise SdpException(f"Unknown data type: {header >> 4}")
        self.offset += 1

        if tag == 15:
            tag = self._read_number()

        if data_type == SdpDataType.INTEGER_POSITIVE:
            return tag, self._read_number()
        elif data_type == SdpDataType.INTEGER_NEGATIVE:
            return tag, -self._read_number()
        elif data_type == SdpDataType.FLOAT:
            length = self._read_number()
            if length != 4 or self.offset + length > len(self.data):
                raise SdpException("Invalid float length")
            value = struct.unpack("<f", self.data[self.offset:self.offset + length])[0]
            self.offset += length
            return tag, value
        elif data_type == SdpDataType.DOUBLE:
            length = self._read_number()
            if length != 8 or self.offset + length > len(self.data):
                raise SdpException("Invalid double length")
            value = struct.unpack("<d", self.data[self.offset:self.offset + length])[0]
            self.offset += length
            return tag, value
        elif data_type == SdpDataType.STRING:
            length = self._read_number()
            if self.offset + length > len(self.data):
                raise SdpException("Truncated string")
            raw = self.data[self.offset:self.offset + length]
            self.offset += length
            try:
                return tag, raw.decode('utf-8')
            except UnicodeDecodeError:
                return tag, raw
        elif data_type == SdpDataType.LIST:
            length = self._read_number()
            if length > len(self.data) - self.offset:
                raise SdpException("Truncated list")
            value = []
            for _ in range(length):
                if self.offset >= len(self.data):
                    break
                _, item = self._unpack()
                value.append(item)
            return tag, value
        elif data_type == SdpDataType.DICT:
            length = self._read_number()
            if length > len(self.data) - self.offset:
                raise SdpException("Truncated dict")
            value = {}
            for _ in range(length):
                if self.offset >= len(self.data):
                    break
                _, k = self._unpack()
                if self.offset >= len(self.data):
                    break
                _, v = self._unpack()
                if isinstance(k, (int, str, bytes, float, tuple)):
                    value[k] = v
            return tag, value
        elif data_type == SdpDataType.STRUCT_BEGIN:
            struct_data = {}
            while self.offset < len(self.data):
                sub_tag, sub_value = self._unpack()
                if isinstance(sub_value, SdpDataType) and sub_value == SdpDataType.STRUCT_END:
                    break
                struct_data[sub_tag] = sub_value
            return tag, SdpStruct(struct_data, _pack=False)
        elif data_type == SdpDataType.STRUCT_END:
            return tag, SdpDataType.STRUCT_END
        else:
            raise SdpException(f"Unknown data type: {data_type}")

    def __repr__(self):
        return f"SdpStruct({dict(self)})"

    def copy(self):
        return SdpStruct(super().copy())

    def update(self, other):
        super().update(other)
        self._pack_to_binary()


_RANK_DEFINITIONS = [
    (0, 3, "Warrior III"), (4, 7, "Warrior II"), (8, 11, "Warrior I"),
    (12, 16, "Elite III"), (17, 21, "Elite II"), (22, 26, "Elite I"),
    (27, 31, "Master IV"), (32, 36, "Master III"), (37, 41, "Master II"), (42, 46, "Master I"),
    (47, 52, "Grandmaster V"), (53, 58, "Grandmaster IV"), (59, 64, "Grandmaster III"),
    (65, 70, "Grandmaster II"), (71, 76, "Grandmaster I"),
    (77, 82, "Epic V"), (83, 88, "Epic IV"), (89, 94, "Epic III"),
    (95, 100, "Epic II"), (101, 106, "Epic I"),
    (107, 112, "Legend V"), (113, 118, "Legend IV"), (119, 124, "Legend III"),
    (125, 130, "Legend II"), (131, 136, "Legend I"),
]


def map_rank(p: int) -> str:
    for lo, hi, name in _RANK_DEFINITIONS:
        if lo <= p <= hi:
            return name
    if 137 <= p <= 161:
        return f"Mythic {p - 136}"
    if 162 <= p <= 186:
        return f"Mythical Honor {p - 136}"
    if 187 <= p <= 236:
        return f"Mythical Glory {p - 136}"
    if 237 <= p <= 9999:
        return f"Mythical Immortal {p - 136}"
    return "Unknown"


def extract_player_data(result, role_info=None, creation_ts=0) -> Optional[Dict]:
    """Lean extractor: Game ID (player_id, server), skin count, and rank (plus level/nickname)."""
    if not isinstance(result, dict) or not result.get(0) or len(result[0]) == 0:
        return None
    try:
        player = result[0][0]
        ri = role_info if isinstance(role_info, dict) else {}
        tag_8 = player.get(8) if player.get(8) is not None else ri.get(6)
        tag_95 = player.get(95) if player.get(95) is not None else ri.get(15)
        skin = player.get(83)
        if skin is None:
            skin = ri.get(10, 0)
        return {
            'status': 'success',
            'data': {
                'basic_info': {
                    'nickname': player.get(2, 'Unknown'),
                    'player_id': player.get(0, 'Unknown'),
                    'server': player.get(1, 'Unknown'),
                    'level': player.get(3, ri.get(3, 0)),
                    'skin_count': skin,
                },
                'game_info': {
                    'current_rank': map_rank(tag_8) if isinstance(tag_8, int) else 'Unknown',
                    'high_rank': map_rank(tag_95) if isinstance(tag_95, int) else 'Unknown',
                },
            },
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# DeviceManager
# FIX: _load() now deduplicates entries and validates minimum length (88 chars).
# Original only checked startswith('and_'); duplicates would waste rotation
# slots and a malformed short entry could produce empty imei_md5/android_id.
# ---------------------------------------------------------------------------

#: Minimum valid device-string length (supports both 88-char and short `and_...` devices in devices.txt).
_DEVICE_MIN_LEN = 5
_SESSION_RESOLVER_DEVICE = "and_8f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0123456789abcdef01234567-0123-4567-89ab-cdef0123"


class DeviceManager:
    def __init__(self, devices_file: str = "devices.txt"):
        self.devices = self._load(devices_file)
        self.lock = threading.Lock()
        self.failed_devices: set = set()
        self.device_usage: Dict[str, int] = defaultdict(int)

    @staticmethod
    def _load(filename: str) -> List[str]:
        """Load device strings from *filename*.

        Changes from original:
        - Deduplicates entries (set-based seen tracker).
        - Skips entries shorter than _DEVICE_MIN_LEN (avoids feeding truncated
          strings to GameConnection which would produce empty imei_md5 /
          android_id fields).
        - Catches UnicodeDecodeError separately so a corrupt file produces a
          clear warning rather than silently falling back.
        """
        devices: List[str] = []
        seen: set = set()
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if (
                        line.startswith(('and_', 'ios_'))
                        and len(line) >= _DEVICE_MIN_LEN
                        and line not in seen
                    ):
                        seen.add(line)
                        devices.append(line)
        except FileNotFoundError:
            pass
        except UnicodeDecodeError as exc:
            import sys
            print(
                f"[DeviceManager] WARNING: could not decode {filename!r}: {exc}",
                file=sys.stderr,
            )
        if not devices:
            devices = [
                "and_8f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0123456789abcdef01234567-0123-4567-89ab-cdef0123",
            ]
        return devices

    def get_next_device(self, exclude_device: Optional[str] = None) -> Optional[str]:
        with self.lock:
            if not self.devices:
                return None
            avail = [d for d in self.devices if d != exclude_device and d not in self.failed_devices]
            if not avail and self.failed_devices:
                self.failed_devices.clear()
                avail = [d for d in self.devices if d != exclude_device]
            if not avail:
                avail = list(self.devices)
            device = random.choice(avail)
            self.device_usage[device] += 1
            return device

    def mark_device_failure(self, device_id: str):
        with self.lock:
            self.failed_devices.add(device_id)

    def reset_device_failure(self, device_id: str):
        with self.lock:
            self.failed_devices.discard(device_id)


class BaseConnection:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sequence = 1
        self.socket: Optional[socket.socket] = None
        self.queue_data = b''

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.cleanup()

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(3)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect((self.host, self.port))

    def cleanup(self):
        if self.socket:
            try:
                self.socket.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0)
                )
                self.socket.close()
            except Exception:
                pass
            self.socket = None
            self.sequence = 1
        self.queue_data = b''

    def send_data(self, cmd_id: int, sdp: SdpStruct):
        packet = SdpStruct({0: cmd_id, 1: self.sequence, 5: sdp.data}).data
        buf = zstd.compress(packet)
        flags = (len(buf) + 4) | (16 << 24)
        self.socket.sendall(flags.to_bytes(4, 'big') + buf)
        self.sequence += 1

    def recv_data(self) -> Tuple[Optional[int], Optional[SdpStruct]]:
        try:
            while len(self.queue_data) < 4:
                try:
                    data = self.socket.recv(4096)
                    if not data:
                        return None, None
                    self.queue_data += data
                except socket.timeout:
                    return -1, None

            flags = int.from_bytes(self.queue_data[:4], 'big')
            size = flags & 0xFFFFFF
            compression_type = flags >> 24
            if size < 4 or size > 16 * 1024 * 1024:
                self.queue_data = b''
                return None, None

            wait_count = 0
            while len(self.queue_data) < size:
                try:
                    data = self.socket.recv(4096)
                    if not data:
                        self.queue_data = b''
                        return None, None
                    self.queue_data += data
                    wait_count = 0
                except socket.timeout:
                    wait_count += 1
                    if wait_count >= 2:
                        self.queue_data = b''
                        return -1, None

            data = self.queue_data[4:size]
            self.queue_data = self.queue_data[size:]

            if compression_type == 1:
                data = zlib.decompress(data)
            elif compression_type == 16:
                data = zstd.decompress(data)
            elif compression_type in (2, 3, 18):
                blk = len(data) - (len(data) % 16)
                if blk <= 0:
                    return None, None
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
                raw_dec = cipher.decrypt(data[:blk])
                if compression_type == 2:
                    data = raw_dec.rstrip(b'\x00')
                elif compression_type == 3:
                    try:
                        data = zlib.decompress(raw_dec)
                    except zlib.error:
                        data = zlib.decompress(raw_dec.rstrip(b'\x00'))
                else:
                    try:
                        data = zstd.decompress(raw_dec.rstrip(b'\x00'))
                    except Exception:
                        data = zstd.ZstdDecompressor().decompressobj().decompress(raw_dec)

            result = SdpStruct(data)
            cmd = result.get(0)
            if cmd is None:
                return None, None

            res = result.get(6) or result.get(5)
            if isinstance(res, str):
                res = res.encode('utf-8', errors='surrogateescape')
            if not res or not isinstance(res, bytes):
                return cmd, None

            return cmd, SdpStruct(res)

        except socket.timeout:
            return -1, None
        except Exception:
            return None, None


class GameConnection(BaseConnection):

    LOGIN_HOST = 'login.ml.youngjoygame.com'
    LOGIN_PORT = 30021

    def __init__(self, device_id: str, device_model: Optional[str] = None,
                 device_manager: Optional[DeviceManager] = None):
        super().__init__(self.LOGIN_HOST, self.LOGIN_PORT)
        self.device_id = device_id
        self.device_model = device_model or random.choice(DEVICE_MODELS)
        self.device_manager = device_manager

        parts = self.device_id.split('_')
        device_info = '_'.join(parts[1:]) if len(parts) >= 2 else device_id
        self.imei_md5 = device_info[:32] if len(device_info) >= 32 else device_info
        self.android_id = device_info[32:48] if len(device_info) >= 48 else ""
        self.advertising_id = device_info[48:] if len(device_info) > 48 else ""

        self.channel = 'and_usa'
        self.client_version = '2.1.95.1232.1'
        self.game_version = self.client_version
        self.account_id = 0
        self.session_key = ''
        self.zone_id = 0
        self.game_server_host = ''
        self.game_server_port = 0
        self.creation_ts = 0

    def login_to_login_server(self) -> bool:
        try:
            if self.host != self.LOGIN_HOST or self.port != self.LOGIN_PORT:
                self.cleanup()
                self.host = self.LOGIN_HOST
                self.port = self.LOGIN_PORT
                self.connect()

            login_data = SdpStruct({
                0: self.device_id,
                1: (f'gps_adid={self.advertising_id}'
                    f'&android_id={self.android_id}'
                    f'&device_unique_id={self.imei_md5}'),
                2: self.client_version,
                3: self.channel,
                4: 'en',
            })
            self.send_data(1, login_data)

            cmd, res = self.recv_data()
            if cmd == 2 and res:
                self.account_id = res.get(0)
                self.session_key = res[1]
                self.zone_id = res[2][0]
                self.creation_ts = res.get(19, 0)
                return True
        except Exception:
            pass
        return False

    def get_game_server(self) -> bool:
        try:
            req = SdpStruct({
                0: self.account_id, 1: self.session_key, 2: self.client_version,
                5: self.zone_id, 6: self.channel,
            })
            self.send_data(5, req)
            cmd, res = self.recv_data()
            if cmd == 6 and res:
                host_port = res[1]
                self.game_server_host, port_str = host_port.split(':')
                self.game_server_port = int(port_str)
                self.game_version = str(res.get(2) or self.client_version)
                return True
        except Exception:
            pass
        return False

    def connect_to_game_server(self, max_retries: int = 5, deadline: Optional[float] = None) -> bool:
        for attempt in range(max_retries):
            if deadline is not None and time.monotonic() >= deadline:
                break
            try:
                self.cleanup()
                self.host = self.game_server_host
                self.port = self.game_server_port
                self.connect()

                auth = SdpStruct({
                    0: self.account_id, 1: self.session_key, 2: self.zone_id,
                    4: self.game_version, 13: self.channel, 15: self.device_id,
                })
                self.send_data(10001, auth)
                self.send_data(10101, SdpStruct({0: 0, 2: 2}))

                timeout_count = 0
                while timeout_count < 2:
                    if deadline is not None and time.monotonic() >= deadline:
                        break
                    cmd, ac_res = self.recv_data()
                    if cmd is None:
                        break
                    if cmd == 10002:
                        return True
                    if cmd == -1:
                        timeout_count += 1
                        break

                if attempt < max_retries - 1 and (deadline is None or time.monotonic() < deadline):
                    time.sleep(1)
            except Exception:
                if attempt < max_retries - 1 and (deadline is None or time.monotonic() < deadline):
                    time.sleep(1)
        return False

    def get_account_info(self, guid: int, session: str,
                         account_type: str = "and", deadline: Optional[float] = None) -> Optional[SdpStruct]:
        try:
            payloads = [
                SdpStruct({
                    0: f"mt-{account_type}_{guid}",
                    1: f"token={session}&name=&id={guid}&nid=",
                    2: 0,
                }),
                SdpStruct({
                    0: f"mt-{account_type}_{guid}",
                    1: f"token={session}",
                    2: 0,
                }),
                SdpStruct({
                    0: str(guid),
                    1: session,
                    2: 0,
                })
            ]

            for req in payloads:
                if deadline is not None and time.monotonic() >= deadline:
                    break
                self.send_data(10207, req)

                timeout_count = 0
                while timeout_count < 2:
                    if deadline is not None and time.monotonic() >= deadline:
                        break
                    cmd, res = self.recv_data()
                    if cmd is None or cmd == 20001:
                        break
                    if cmd == -1:
                        timeout_count += 1
                        continue
                    if cmd == 10208:
                        if res and res.get(2):
                            return res
                        break
        except Exception:
            pass
        return None

    def get_highest_level_role(self, account_result) -> Tuple[Optional[int], Optional[int]]:
        if not account_result:
            return None, None
        role_list = account_result.get(2)
        if not role_list:
            return None, None

        highest_role = None
        highest_level = -1

        for role in role_list:
            if isinstance(role, dict):
                zone = role.get(0, 0)
                rid = role.get(1, 0)
                lvl = role.get(3, 0)
            else:
                zone = role[0] if len(role) > 0 else 0
                rid = role[1] if len(role) > 1 else 0
                lvl = role[3] if len(role) > 3 else 0

            if lvl > highest_level:
                highest_level = lvl
                highest_role = (rid, zone)

        return highest_role if highest_role else (None, None)

    def get_role_detail(self, role_id: int) -> Optional[SdpStruct]:
        try:
            self.send_data(11153, SdpStruct({1: role_id}))
            timeout_count = 0
            while timeout_count < 2:
                cmd, res = self.recv_data()
                if cmd is None:
                    break
                if cmd == -1:
                    timeout_count += 1
                    continue
                if cmd == 11154:
                    return res
        except Exception:
            pass
        return None

    def get_role_info(self, role_id: int, zone_id: int) -> Optional[SdpStruct]:
        try:
            self.send_data(10143, SdpStruct({0: role_id, 1: zone_id}))
            timeout_count = 0
            while timeout_count < 2:
                cmd, res = self.recv_data()
                if cmd is None:
                    break
                if cmd == -1:
                    timeout_count += 1
                    continue
                if cmd == 10144:
                    return res
        except Exception:
            pass
        return None

    def filter_by_server(self, result, target_server):
        if not result or not result.get(0):
            return None
        players_list = result[0]
        for player in players_list:
            if isinstance(player, dict):
                player_server = player.get(1)
                if player_server == target_server:
                    return {0: [player]}
        return None


def _role_detail_from_info(role_id: int, zone_id: int, role_info: Dict) -> Dict:
    return {0: [{
        0: role_id, 1: zone_id,
        2: role_info.get(2, 'Unknown'), 3: role_info.get(3, 0),
        8: role_info.get(6), 95: role_info.get(15),
        83: role_info.get(10, 0),
    }]}


def get_player_info(
    guid: int,
    session: str,
    device_manager: DeviceManager,
    max_device_retries: int = 20,
) -> Optional[Dict]:
    """Fast lookup ONLY for Game ID (role_id, zone_id), skin count, and rank. Use full_info.py for full profile."""
    result = None
    role_id, zone_id = None, None
    deadline = time.monotonic() + 13.5  # ponytail: exit before browser.py 15s wait_for so executor threads never leak
    resolver_devs = [d for d in device_manager.devices if len(d) >= 88] or [_SESSION_RESOLVER_DEVICE]
    for rdev in resolver_devs[:3]:
        if time.monotonic() >= deadline:
            break
        rconn: Optional[GameConnection] = None
        try:
            rconn = GameConnection(device_id=rdev, device_manager=device_manager)
            rconn.connect()
            if not (rconn.login_to_login_server() and rconn.get_game_server() and rconn.connect_to_game_server(max_retries=2, deadline=deadline)):
                continue
            for atype in ("and", "ios"):
                if time.monotonic() >= deadline:
                    break
                cand = rconn.get_account_info(guid, session, atype, deadline=deadline)
                if cand:
                    rid, zid = rconn.get_highest_level_role(cand)
                    if rid:
                        result, role_id, zone_id = cand, rid, zid
                        # Fast path: query basic role_info (ID, skin, rank) on same open connection (0 extra TCP handshake)
                        ri = rconn.get_role_info(rid, zid)
                        if ri and (ri.get(6) is not None or ri.get(10) is not None):
                            pd = extract_player_data(_role_detail_from_info(rid, zid, ri), ri, 0)
                            if pd:
                                return pd
                        break
            if role_id:
                break
        except Exception:
            pass
        finally:
            if rconn:
                rconn.cleanup()

    if not result or not role_id:
        return None

    used_devices: List[str] = []
    for attempt in range(1, max_device_retries + 1):
        if time.monotonic() >= deadline:
            break
        exclude = used_devices[-1] if used_devices else None
        device_id = device_manager.get_next_device(exclude)
        if not device_id:
            break

        used_devices.append(device_id)
        conn: Optional[GameConnection] = None

        try:
            conn = GameConnection(device_id=device_id, device_manager=device_manager)
            conn.connect()

            if not conn.login_to_login_server():
                device_manager.mark_device_failure(device_id)
                conn.cleanup()
                continue

            if not conn.get_game_server() or not conn.connect_to_game_server(deadline=deadline):
                conn.cleanup()
                continue

            role_info = conn.get_role_info(role_id, zone_id)
            has_core = bool(role_info and (role_info.get(6) is not None or role_info.get(10) is not None))
            role_detail = _role_detail_from_info(role_id, zone_id, role_info) if has_core else conn.get_role_detail(role_id)
            if not role_detail:
                conn.cleanup()
                continue

            player_data = extract_player_data(role_detail, role_info, 0)
            conn.cleanup()
            if player_data:
                return player_data
        except Exception:
            if conn:
                conn.cleanup()
            continue

    return None
