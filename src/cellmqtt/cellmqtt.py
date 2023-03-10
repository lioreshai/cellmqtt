import os
import math
import time
import random
import serial
import logging
import schedule
import configparser
import mqtt_codec.packet

from enum import Enum
from io import BytesIO
from typing import Callable, Tuple


config = configparser.ConfigParser()
config.read(os.getcwd() + '/config.ini')

#Constants used to recognize MQTT packets
MQTT_PKT_TYPE_MASK = 0xF0
MQTT_PUBLISH = 0x30
MQTT_PINGREQ = b"\xc0\0"
MQTT_PINGRESP = 0xD0
MQTT_SUB = b"\x82"
MQTT_SUBACK = 0x90
MQTT_UNSUB = b"\xA2"
MQTT_DISCONNECT = b"\xe0\0"
MQTT_CONNACK = 0x20

class WirelessChip(Enum):
    SIM800C = 1

class MQTTPacketException(Exception):
    """ Malformed or unexpected packets read off the serial bus
    """
    pass

#An actual error received from the MQTT broker, possible error codes:
class MQTTServerException(Exception):
    """ Malformed or unexpected packets read off the serial bus
    	
    * 0x01 Connection Refused, unacceptable protocol version
    * 0x02 Connection Refused, identifier rejected
    * 0x03 Connection Refused, Server unavailable
    * 0x04 Connection Refused, bad user name or password
    * 0x05 Connection Refused, not authorized
    """
    pass

class CellMQTT:
    _sub_handlers = {}
    _publish_jobs = []
    _queued_publish_bytes = 0

    def __init__(self, 
    log_level =  logging.INFO, 
    serial_path: str = config['SERIAL_PORT']['SerialPath'], 
    baud_rate: int = config['SERIAL_PORT']['BaudRate'], 
    timeout: int = config['SERIAL_PORT']['Timeout'], 
    cell_chip: WirelessChip = WirelessChip.SIM800C, 
    cell_apn: int = config['CELLULAR']['APN']):
        """ Initialize a MQTT client object

        Args:
            log_level (LogLevel, optional): [description]. Defaults to LogLevel.INFO.
            serial_path (str, optional): Path to the serial port cellular module is connected to. Defaults to config['SERIAL_PORT']['SerialPath'].
            baud_rate (int, optional):  Baud rate for your cell chip - check datasheet. Defaults to config['SERIAL_PORT']['BaudRate'].
            timeout (int, optional): Timeout for serial client - best to leave at 1s. Defaults to config['SERIAL_PORT']['Timeout'].
            cell_chip (WirelessChip, optional): Defaults to WirelessChip.SIM800C.
            cell_apn (int, optional): [description]. APN for your cellular provider. Defaults to config['CELLULAR']['APN'].
        """
        self._ser = serial.Serial(serial_path, baud_rate, timeout = int(timeout))
        self._cell_chip = cell_chip
        self._cell_apn = cell_apn
        logging.basicConfig(level=log_level, format='%(asctime)s [%(levelname)s] %(message)s', )
        self._log = logging.getLogger(__name__)

    def _sim800c_format_at(self, data: str) -> bytes:
        data = 'AT+' + data + '\r\n'
        return data.encode()

    def _sim800c_tcp_connect(self, host: str, port: int, tls: bool = False) -> None:
        self._log.info('Establishing TCP connection...')
        self._serial_write_at_cmd('CIPCLOSE', wait_time=2)
        self._serial_write_at_cmd('CIPSHUT', wait_time=2)
        self._serial_write_at_cmd('CSTT="{}"'.format(self._cell_apn), wait_time=2)
        self._serial_write_at_cmd('CIICR', wait_time=2)
        self._serial_write_at_cmd('CIFSR', wait_time=2)
        if tls:
            self._serial_write_at_cmd('CIPSSL=1', wait_time=2)
        self._serial_write_at_cmd('CIPSTART="TCP","' + host + '",' + str(port), wait_time=3)
        connected = self._serial_await_response(b'CONNECT OK')
        if not connected:
            raise Exception('could not establish tcp connection with server')
        self._log.info('TCP connection established.')

    def _sim800c_tcp_send(self, data: bytes) -> None:
        attempts: int = 0
        ready_to_send: bool = False
        # Wait for the ">" char to be read from serial to signal tcp write ready
        while not ready_to_send:
            if attempts > 5:
                raise Exception('error initiating tcp send')
            self._serial_write_at_cmd('CIPSEND=' + str(len(data)), wait_time=0)
            ready_to_send = self._serial_await_response(b'>')
            if attempts:
                time.sleep(1)
            attempts += 1
        self._ser.write(data)
        # Write Ctrl-Z to signal end of write
        self._ser.write(chr(26).encode('utf-8'))
        if not self._serial_await_response(b"SEND OK"):
            self._log.warn('tcp send did not return expected "SEND OK"')

    def _at_disable_echo_sim800c(self) -> None:
        self._ser.write('ATE0\r\n'.encode())

    def _serial_setup_device(self) -> None:
        self._at_disable_echo_sim800c()

    def _serial_write_at_cmd(self, data: str, wait_time: float = .4) -> None:
        self._ser.write(self._sim800c_format_at(data))
        self._log.debug(str(data))
        if(wait_time):
            time.sleep(wait_time)

    def _serial_await_response(self, expected: bytes) -> bool:
        result = self._ser.read_until(expected)[-len(expected):]
        self._log.debug('Expected:' + str(expected))
        self._log.debug('Result:' + str(result))
        return result == expected

    def _tcp_connect(self, host: str, port: int, tls: bool = False) -> None:
        self._sim800c_tcp_connect(host, port, tls)

    def _tcp_send(self, data: bytes) -> None:
        self._sim800c_tcp_send(data)

    def _mqtt_generate_pid(self) -> int:
        return random.randint(0,65535)

    # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718033
    def _mqtt_process_connack(self, packet: bytearray) -> Tuple[bool, int]:
        """
        Returns:
            Tuple[bool, int]: Returns the SP (session present) flag and server return code
        """
        self._log.debug('connack packet: ' + str(packet))
        if packet[0] & MQTT_PKT_TYPE_MASK != MQTT_CONNACK:
            raise MQTTPacketException('connack error: invalid control packet type')
        if(packet[3] != 0x00):
            raise MQTTServerException('connack error: server refused connection with error code: ' + str(packet[2]))
        return [packet[2], packet[3]]

    def _mqtt_await_fixed_header(self, type, timeout: int = 5) -> bytes:
        res = bytearray(1)
        stamp = time.monotonic()
        while res[0] != type:
            res = self._ser.read(1)
            if res and res[0] & MQTT_PKT_TYPE_MASK == type:
                return res
            time.sleep(.01)
            if time.monotonic() - stamp > timeout:
                raise MQTTPacketException("timed out waiting for " + str(type) + " fixed header byte")

    def _mqtt_ping(self) -> None:
        self._tcp_send(b'\xc0\x00')
        self._mqtt_await_fixed_header(MQTT_PINGRESP)
        self._log.debug('mqtt ping got response from broker')

    # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718023
    def _mqtt_get_remaining_len(self) -> int:
        len = 0
        offset = 0
        read_byte = bytearray(1)
        while True:
            read_byte = self._ser.read(1)[0]
            len |= (read_byte & 0x7F) << offset
            if not read_byte & 0x80:
                return len
            offset += 7

    def _mqtt_process_incoming_message(self, first_byte: int) -> Tuple[str, bytes, int]:
        """
        Returns:
            Tuple[str, bytes, int]: topic name, message payload, packet ID (PID)
        """
        remaining_len = self._mqtt_get_remaining_len()
        topic_len = self._ser.read(2)
        topic_len = (topic_len[0] << 8) | topic_len[1]
        if topic_len > remaining_len:
            raise MQTTPacketException('packet error: topic length is greater than remaining length')
        topic = str(self._ser.read(topic_len), 'utf-8')
        remaining_len -= topic_len + 2
        pid = 0
        # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718039
        if first_byte & 0x06:
            pid = self._ser.read(2)
            pid = pid[0] << 0x08 | pid[1]
            remaining_len -= 0x02
        return [topic, self._ser.read(remaining_len), pid]

    def _mqtt_poll_incoming_message(self) -> None:
        res = self._ser.read(1)
        if res in [None, b"", b"\x00"]:
            return None
        # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718018
        if res[0] & MQTT_PKT_TYPE_MASK == MQTT_PUBLISH:
            [topic, payload, pid] = self._mqtt_process_incoming_message(res[0])
            if topic in self._sub_handlers:
                self._sub_handlers[topic](topic, payload)
            self._log.debug('got message for topic: ' + topic )
            self._log.debug('payload: ' + str(payload, "utf-8") )
            self._log.debug('pid: ' + str(pid) )

    def _mqtt_send_queued_publish_jobs(self) -> None:
        if self._queued_publish_bytes:
            payload = b""
            while len(self._publish_jobs):
                payload = payload + self._publish_jobs.pop()
            self._tcp_send(payload)
            self._queued_publish_bytes=0

    def connect(self, 
    client_id: str = config['MQTT_BROKER']['MQTTClientID'], 
    host: str = config['MQTT_BROKER']['MQTTHost'], 
    port: int = config['MQTT_BROKER']['MQTTPort'], 
    username: str = config['MQTT_BROKER']['MQTTUsername'], 
    password: str = config['MQTT_BROKER']['MQTTPassword'], 
    keep_alive: int = int(config['MQTT_BROKER']['MQTTKeepAlive']), 
    tls: bool = config['MQTT_BROKER']['MQTTSSL']):
        """ Connect to an MQTT broker via the cellular chip.

        Args:
            client_id (str, optional): Defaults to config['MQTT_BROKER']['MQTTClientID'].
            host (str, optional): Defaults to config['MQTT_BROKER']['MQTTHost'].
            port (int, optional): Defaults to config['MQTT_BROKER']['MQTTPort'].
            username (str, optional): Defaults to config['MQTT_BROKER']['MQTTUsername'].
            password (str, optional): Defaults to config['MQTT_BROKER']['MQTTPassword'].
            keep_alive (int, optional): Recommended to use a keep_alive interval. Defaults to int(config['MQTT_BROKER']['MQTTKeepAlive']).
            tls (bool, optional): Defaults to config['MQTT_BROKER']['MQTTSSL'].
        """
        self._log.info('Attempting connection to MQTT broker...')
        self._serial_setup_device()
        self._tcp_connect(host, port, tls=tls)
        self._mqtt_keepalive = keep_alive
        connect = mqtt_codec.packet.MqttConnect(client_id=client_id, clean_session=False, keep_alive=30, username=username, password=password)
        with BytesIO() as f:
            connect.encode(f)
            buf = f.getvalue()
            self._tcp_send(buf)
            connack_packet = self._ser.read(6)[-4:]
            self._log.debug("Got connack: " + str(connack_packet))
            [session_present, return_code] = self._mqtt_process_connack(connack_packet)
            if(keep_alive is not None):
                schedule.every(math.ceil(keep_alive/2)).seconds.do(self._mqtt_ping)
            self._log.info('Sucessfully connected to MQTT broker.')
            self._log.debug('Session Present: ' + str(session_present))
            self._log.debug('Return Code: ' + str(return_code))

    def publish(self, topic: str, message: bytearray, dupe: bool = False, qos: int = 0, retain: bool = False):
        publish = mqtt_codec.packet.MqttPublish(0 if not qos else self._mqtt_generate_pid(), topic, message.encode(), dupe, qos, retain)
        with BytesIO() as f:
            num_bytes_written = publish.encode(f)
            buf = f.getvalue()
            self._publish_jobs.append(buf)
            self._queued_publish_bytes = self._queued_publish_bytes + num_bytes_written

    def subscribe(self, topic: str, handler: Callable[[str,bytes],None], max_qos=0):
        """ Subscribe to a MQTT topic

        Args:
            topic (str)
            handler (Callable[[str,bytes],None]): This function will be called when a message arrives on this topic
              > The function should accept two arguments: topic (str) and message (bytes)
        """
        pid = 0 if not max_qos else self._mqtt_generate_pid()
        subscribe = mqtt_codec.packet.MqttSubscribe(pid, [mqtt_codec.packet.MqttTopic(topic, max_qos)])
        with BytesIO() as f:
            subscribe.encode(f)
            buf = f.getvalue()
            self._tcp_send(buf)
            res = self._ser.read(6)[-4:]
            remaining_len = res[1]
            payload = self._ser.read(remaining_len-2)
            if res[0] & MQTT_PKT_TYPE_MASK != MQTT_SUBACK:
                raise MQTTPacketException('subscription error: invalid suback header')
            # Validate this suback is for given PID
            if res[2] << 8 | res[3] != pid:
                raise MQTTPacketException('subscription error: incorrect suback pid value')
            self._log.debug('suback packet: ' + str(res))
            self._log.info('Subscribed to topic: "' + topic + '" Return code: ' + str(payload))
            self._sub_handlers[topic] = handler

    def loop(self):
        while True:
            schedule.run_pending()
            self._mqtt_poll_incoming_message()
            self._mqtt_send_queued_publish_jobs()