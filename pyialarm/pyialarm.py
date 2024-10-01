import logging
from datetime import datetime
import re
import socket
from collections import OrderedDict
import asyncio
import dicttoxml2
import xmltodict
from typing import List
from pyialarm.const import (
    LogEntryType,
    EVENT_TYPE_MAP,
    StatusType,
    ZoneStatusType,
    ZoneTypeEnum,
    SirenSoundTypeEnum,
    ZONE_TYPE_MAP,
    ALARM_TYPE_MAP,
    ZoneType,
)

log = logging.getLogger(__name__)
# dicttoxml is very verbose at INFO level
logging.getLogger("dicttoxml").setLevel(logging.CRITICAL)


class IAlarm(object):
    """
    Interface the iAlarm security systems.
    """

    ARMED_AWAY = 0
    DISARMED = 1
    ARMED_STAY = 2
    CANCEL = 3
    TRIGGERED = 4

    def __init__(self, host, port=18034):
        """
        :param host: host of the iAlarm security system (e.g. its IP address)
        :param port: port of the iAlarm security system (should be '18034')
        """
        self.host = host
        self.port = port
        self.seq = 0
        self.sock = None

    async def ensure_connection_is_open(self) -> None:
        if self.sock is None or self.sock.fileno() == -1:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setblocking(False)
        else:
            return

        self.seq = 0
        try:
            await asyncio.get_event_loop().sock_connect(
                self.sock, (self.host, self.port)
            )
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError) as err:
            self.sock.close()
            raise ConnectionError("Connection to the alarm system failed") from err

    def _close_connection(self) -> None:
        if self.sock and self.sock.fileno() != 1:
            self.sock.close()

    async def _receive(self):
        try:
            loop = asyncio.get_event_loop()
            data = await loop.sock_recv(self.sock, 1024)

            log.debug(f"Raw data from socket: {data}")

        except (asyncio.TimeoutError, OSError, ConnectionRefusedError) as err:
            self.sock.close()
            raise ConnectionError("Connection error") from err

        if not data:
            self.sock.close()
            raise ConnectionError("Connection error, received no reply")

        payload = data[16:-4]
        log.debug(f"Extracted payload: {payload}")

        decoded = (
            self._xor(payload).decode(errors="ignore").replace("<Err>ERR|00</Err>", "")
        )

        log.debug(f"Decoded data: {decoded}")

        if not decoded:
            self.sock.close()
            raise ConnectionError("Connection error, received an unexpected reply")

        try:
            return xmltodict.parse(
                decoded,
                xml_attribs=False,
                dict_constructor=dict,
                postprocessor=self._xmlread,
            )
        except Exception as e:
            log.error(f"Error parsing XML: {decoded}")
            raise e

    async def _send_request_list(self, xpath, command, offset=0, partial_list=None):
        if offset > 0:
            command["Offset"] = "S32,0,0|%d" % offset
        root_dict = self._create_root_dict(xpath, command)
        await self._send_dict(root_dict)
        response = await self._receive()

        if partial_list is None:
            partial_list = []
        total = self._clean_response_dict(response, "%s/Total" % xpath)
        ln = self._clean_response_dict(response, "%s/Ln" % xpath)
        for i in list(range(ln)):
            partial_list.append(
                self._clean_response_dict(response, "%s/L%d" % (xpath, i))
            )
        offset += ln
        if total > offset:
            await self._send_request_list(xpath, command, offset, partial_list)

        return partial_list

    async def _send_request(self, xpath, command) -> dict:
        root_dict = self._create_root_dict(xpath, command)
        await self._send_dict(root_dict)
        response = await self._receive()
        self._close_connection()
        return self._clean_response_dict(response, xpath)

    async def get_mac(self) -> str:
        mac = ""
        command = OrderedDict()
        command["Mac"] = None
        command["Name"] = None
        command["Ip"] = None
        command["Gate"] = None
        command["Subnet"] = None
        command["Dns1"] = None
        command["Dns2"] = None
        command["Err"] = None
        network_info = await self._send_request("/Root/Host/GetNet", command)

        if network_info is not None:
            mac = network_info.get("Mac", "")

        if mac:
            return mac
        else:
            raise ConnectionError(
                "An error occurred trying to connect to the alarm "
                "system or received an unexpected reply"
            )

    def get_last_log_entries(self, log: List[LogEntryType]) -> List[LogEntryType]:
        if not log:
            return []
        return log[:25]

    async def get_zone_status(self) -> list[ZoneStatusType]:
        zones: list[ZoneType] = await self.get_zone()

        zone_name_map = {zone["zone_id"]: zone["name"] for zone in zones}

        command: dict = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None
        zone_status: list[int] = await self._send_request_list(
            "/Root/Host/GetByWay", command
        )

        if zone_status is None:
            raise ConnectionError(
                "An error occurred trying to connect to the alarm system"
            )

        result = []
        for i, status in enumerate(zone_status):
            zone_id = i + 1

            status_list = []

            if status & StatusType.ZONE_IN_USE:
                status_list.append(StatusType.ZONE_IN_USE)
            if status & StatusType.ZONE_ALARM:
                status_list.append(StatusType.ZONE_ALARM)
            if status & StatusType.ZONE_BYPASS:
                status_list.append(StatusType.ZONE_BYPASS)
            if status & StatusType.ZONE_FAULT:
                status_list.append(StatusType.ZONE_FAULT)
            if status & StatusType.ZONE_LOW_BATTERY:
                status_list.append(StatusType.ZONE_LOW_BATTERY)
            if status & StatusType.ZONE_LOSS:
                status_list.append(StatusType.ZONE_LOSS)

            if not status_list:
                status_list.append(StatusType.ZONE_NOT_USED)

            zone_name = zone_name_map.get(zone_id, "Unknown")

            zone_item: ZoneStatusType = {
                "zone_id": zone_id,
                "name": zone_name,
                "types": status_list,
            }
            result.append(zone_item)

        return result

    async def get_status(self) -> int:
        command = OrderedDict()
        command["DevStatus"] = None
        command["Err"] = None

        alarm_status: dict = await self._send_request(
            "/Root/Host/GetAlarmStatus", command
        )

        if alarm_status is None:
            raise ConnectionError(
                "An error occurred trying to connect to the alarm system"
            )

        status = int(alarm_status.get("DevStatus", -1))
        if status == -1:
            raise ConnectionError("Received an unexpected reply from the alarm")

        zone_status: list[ZoneStatusType] = await self.get_zone_status()
        zone_alarm = False

        for zone in zone_status:
            if StatusType.ZONE_ALARM in zone["types"]:
                zone_alarm = True

        if (status == self.ARMED_AWAY or status == self.ARMED_STAY) and zone_alarm:
            return self.TRIGGERED

        return status

    async def get_log(self) -> List[LogEntryType]:
        command = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None

        event_log: List[LogEntryType] = await self._send_request_list(
            "/Root/Host/GetLog", command
        )

        for event in event_log:
            if "DTA,19" in event["Time"]:
                try:
                    time_str = event["Time"].split("|")[1]
                    time_value = datetime.strptime(time_str, "%Y.%m.%d.%H.%M.%S")
                    event["Time"] = time_value
                except (ValueError, IndexError):
                    event["Time"] = event["Time"]

            if "GBA" in event["Name"]:
                try:
                    name_decoded = bytes.fromhex(event["Name"].split("|")[1]).decode(
                        "utf-8", errors="ignore"
                    )
                    event["Name"] = name_decoded
                except (ValueError, IndexError):
                    event["Name"] = event["Name"]

            event["Event"] = EVENT_TYPE_MAP.get(event["Event"], event["Event"])

        return event_log

    def __extract_zones(self, zone_data: list) -> list[ZoneType]:
        zones = []
        for i, zone in enumerate(zone_data, start=1):
            name_decoded = ""
            if "GBA" in zone["Name"]:
                try:
                    name_decoded = bytes.fromhex(zone["Name"].split("|")[1]).decode(
                        "utf-8", errors="ignore"
                    )
                except (ValueError, IndexError):
                    name_decoded = zone["Name"]
            bell_value = True if zone["Bell"] == "BOL|T" else False
            zone_item = ZoneType(
                zone_id=i,
                type=zone["Type"],
                voice=zone["Voice"],
                name=name_decoded,
                bell=bell_value,
            )
            zones.append(zone_item)
        return zones

    async def get_zone(self) -> list[ZoneType]:
        command = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None

        raw_zone_data = await self._send_request_list("/Root/Host/GetZone", command)

        zone: list[ZoneType] = self.__extract_zones(raw_zone_data)

        return zone

    async def get_zone_type(self) -> List[ZoneTypeEnum]:
        command = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None

        zone_type_codes = await self._send_request_list(
            "/Root/Host/GetZoneType", command
        )
        zone_types = [
            ZONE_TYPE_MAP.get(code, ZoneTypeEnum.UNUSED) for code in zone_type_codes
        ]

        return zone_types

    async def get_alarm_type(self) -> List[ZoneType]:
        command = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None

        alarm_type_codes = await self._send_request_list(
            "/Root/Host/GetVoiceType", command
        )
        zone_types = [
            ALARM_TYPE_MAP.get(code, SirenSoundTypeEnum.CONTINUED)
            for code in alarm_type_codes
        ]

        return zone_types

    async def arm_away(self) -> None:
        command = OrderedDict()
        command["DevStatus"] = "TYP,ARM|0"
        command["Err"] = None
        await self._send_request("/Root/Host/SetAlarmStatus", command)

    async def arm_stay(self) -> None:
        command = OrderedDict()
        command["DevStatus"] = "TYP,STAY|2"
        command["Err"] = None
        await self._send_request("/Root/Host/SetAlarmStatus", command)

    async def disarm(self) -> None:
        command = OrderedDict()
        command["DevStatus"] = "TYP,DISARM|1"
        command["Err"] = None
        await self._send_request("/Root/Host/SetAlarmStatus", command)

    async def cancel_alarm(self) -> None:
        command = OrderedDict()
        command["DevStatus"] = "TYP,CLEAR|3"
        command["Err"] = None
        await self._send_request("/Root/Host/SetAlarmStatus", command)

    async def _send_dict(self, root_dict) -> None:
        xml = dicttoxml2.dicttoxml(root_dict, attr_type=False, root=False)

        await self.ensure_connection_is_open()

        self.seq += 1
        msg = b"@ieM%04d%04d0000%s%04d" % (len(xml), self.seq, self._xor(xml), self.seq)
        await asyncio.get_event_loop().sock_sendall(self.sock, msg)

    @staticmethod
    def _xmlread(_path, key, value):
        if value is None or not isinstance(value, str):
            return key, value

        err_re = re.compile(r"ERR\|(\d{2})")
        mac_re = re.compile(r"MAC,(\d+)\|(([0-9A-F]{2}[:-]){5}([0-9A-F]{2}))")
        s32_re = re.compile(r"S32,(\d+),(\d+)\|(\d*)")
        str_re = re.compile(r"STR,(\d+)\|(.*)")
        typ_re = re.compile(r"TYP,(\w+)\|(\d+)")
        if err_re.match(value):
            value = int(err_re.search(value).groups()[0])
        elif mac_re.match(value):
            value = str(mac_re.search(value).groups()[1])
        elif s32_re.match(value):
            value = int(s32_re.search(value).groups()[2])
        elif str_re.match(value):
            value = str(str_re.search(value).groups()[1])
        elif typ_re.match(value):
            value = int(typ_re.search(value).groups()[1])
        # Else: we are not interested in this value, just keep it as is

        return key, value

    @staticmethod
    def _create_root_dict(path, my_dict=None):
        if my_dict is None:
            my_dict = {}
        root = {}
        elem = root
        plist = path.strip("/").split("/")
        k = len(plist) - 1
        for i, j in enumerate(plist):
            elem[j] = {}
            if i == k:
                elem[j] = my_dict
            elem = elem.get(j)
        return root

    @staticmethod
    def _clean_response_dict(response, path):
        for i in path.strip("/").split("/"):
            try:
                i = int(i)
                response = response[i]
            except ValueError:
                response = response.get(i)
        return response

    @staticmethod
    def _xor(xml):
        sz = bytearray.fromhex(
            "0c384e4e62382d620e384e4e44382d300f382b382b0c5a6234384e304e4c372b10535a0c20432d171142444e58422c421157322a204036172056446262382b5f0c384e4e62382d620e385858082e232c0f382b382b0c5a62343830304e2e362b10545a0c3e432e1711384e625824371c1157324220402c17204c444e624c2e12"
        )
        buf = bytearray(xml)
        for i in range(len(xml)):
            ki = i & 0x7F
            buf[i] = buf[i] ^ sz[ki]

        log.debug(f"XOR result: {buf.decode(errors='ignore')}")
        return buf
