
import os
import math
import time
import serial

import logging
import schedule
import configparser
import mqtt_codec.io
import mqtt_codec.packet

from enum import Enum
from io import BytesIO
from typing import Callable


config = configparser.ConfigParser()
config.read(os.getcwd() + '/config.ini')

#Constants used to recognize MQTT packets
MQTT_PKT_TYPE_MASK = 0xF0
MQTT_PUBLISH = 0x30
MQTT_PINGREQ = b"\xc0\0"
MQTT_PINGRESP = 0xD0
MQTT_SUB = b"\x82"
MQTT_SUBACK = 0x40
MQTT_UNSUB = b"\xA2"
MQTT_DISCONNECT = b"\xe0\0"

class WirelessChip(Enum):
    SIM800C = 1

class CMDType(Enum):
    AT = 1
    BYTES = 2

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
    """ Cellular MQTT Library for IoT devices like the Raspberry Pi
    """
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
        logging.basicConfig(level=log_level, format='%(asctime)s - %(message)s', )
        self._log = logging.getLogger(__name__)

    def _format_at_cmd_sim800c(self, data: str) -> bytes:
        """ AT command formatting for SIM800c chip

        Args:
            data (str): The actual command to be sent to the device

        Returns:
            bytes: encoded data to be written to serial bus
        """
        data = 'AT+' + data + '\r\n'
        return data.encode()

    def _at_disable_echo_sim800c(self):
        """ Command to disable echoing on serial bus - without this the SIM800c will echo back all data written to it
        """
        self._ser.write('ATE0\r\n'.encode())

    def _send_at_cmd(self, data: str, wait_time: float = .4):
        """ Send AT command to cellular module

        Args:
            data (str): Raw, unformatted command text
            read (bool, optional): If set to true, the command will read from the bus, even if it is not printing to log. Defaults to True.
        """
        self._ser.write(self._format_at_cmd_sim800c(data))
        self._log.debug(str(data))
        if(wait_time):
            time.sleep(wait_time)

    def _await_serial_response(self, expected: bytes) -> bool:
        result = self._ser.read_until(expected)[-len(expected):]
        self._log.debug('Expected:' + str(expected))
        self._log.debug('Result:' + str(result))
        return result == expected

    def _tcp_connect_sim800c(self, host: str, port: int, tls: bool = False):
        """ Establish a TCP connection to a remote host

        Args:
            host (str)
            port (int)
            tls (bool, optional): When set to True, the SIM800c will attempt TLSv1 negotiation. Note that the chip 
            is unfortunately not capable of any TLS version above TLSv1. Defaults to False.

        Raises:
            Exception: Will be raised when TCP connection can't be negotiated. This can either be caught by user
            or cause the program to exit and be restarted by a supervisor like systemd.
        """
        self._log.info('Establishing TCP connection...')
        self._send_at_cmd('CIPCLOSE', wait_time=2)
        self._send_at_cmd('CIPSHUT', wait_time=2)
        # self._send_at_cmd('CGATT?')
        self._send_at_cmd('CSTT="{}"'.format(self._cell_apn))
        self._send_at_cmd('CIICR', wait_time=2)
        self._send_at_cmd('CIFSR', wait_time=2)
        if tls:
            self._send_at_cmd('CIPSSL=1')
        self._send_at_cmd('CIPSTART="TCP","' + host + '",' + str(port), wait_time=2)
        connected = self._await_serial_response(b'CONNECT OK')
        if not connected:
            raise Exception('could not establish tcp connection with server')
        self._log.info('TCP connection established.')

    def _process_connack(self, packet: bytearray):
        """ Process the MQTT connack packet - see more here: 
        http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718033

        Args:
            packet (bytearray): Raw connack packet to be validated

        Raises:
            MQTTPacketException
            MQTTServerException
        """
        if(len(packet) != 3):
            raise MQTTPacketException('connack error: invalid packet length')
        if(packet[0] != 0x02):
            raise MQTTPacketException('connack error: invalid fixed header in packet')
        if(packet[2] != 0x00):
            raise MQTTServerException('connack error: server refused connection with error code: ' + str(packet[2]))
        self._log.debug('connack packet: ' + str(packet))

    def _wait_for_mqtt_fixed_header(self, header_type, timeout: int = 5) -> bytes:
        """ Wait for a MQTT fixed header 
        """
        res = bytearray(1)
        stamp = time.monotonic()
        while res[0] != header_type:
            res = self._ser.read(1)
            if res[0] & MQTT_PKT_TYPE_MASK == header_type:
                return res
            if time.monotonic() - stamp > timeout:
                raise MQTTPacketException("timed out waiting for " + str(MQTT_SUBACK) + " fixed header byte")

    def _mqtt_ping(self):
        self._tcp_send(b'\xc0\x00')
        self._wait_for_mqtt_fixed_header(MQTT_PINGRESP)
        self._log.debug('mqtt ping got response from broker')


    def _get_remaining_len(self) -> int:
        """ Get the remaining length
            http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718023

        Returns:
            int
        """
        len = 0
        offset = 0
        read_byte = bytearray(1)
        while True:
            read_byte = self._ser.read(1)[0]
            len |= (read_byte & 0x7F) << offset
            if not read_byte & 0x80:
                return len
            offset += 7

    def _check_for_publish_messages(self) -> None:
        """ Read serial bus one byte at a time, waiting for a MQTT_PUBLISH packet to arrive

        Raises:
            MQTTPacketException: Raised if the packet is malformed
        """
        res = self._ser.read(1)
        if res in [None, b"", b"\x00"]:
            return None
        if res[0] & MQTT_PKT_TYPE_MASK == MQTT_PUBLISH:
            remaining_len = self._get_remaining_len()
            topic_len = self._ser.read(2)
            topic_len = (topic_len[0] << 8) | topic_len[1]
            if topic_len > remaining_len:
                raise MQTTPacketException('packet error: topic length is greater than remaining length')
            topic = str(self._ser.read(topic_len), 'utf-8')
            remaining_len -= topic_len + 2
            pid = 0
            if res[0] & 0x06:
                pid = self._ser.read(2)
                pid = pid[0] << 0x08 | pid[1]
                remaining_len -= 0x02
            raw_msg = self._ser.read(remaining_len)
            msg = str(raw_msg, "utf-8")
            if topic in self._sub_handlers:
                self._sub_handlers[topic](topic, raw_msg)
            self._log.debug('got message for topic: ' + topic )
            self._log.debug('payload: ' + msg )

    def _send_queued_publish_jobs(self):
        if self._queued_publish_bytes:
            payload = b""
            while len(self._publish_jobs):
                payload = payload + self._publish_jobs.pop()
            self._tcp_send(payload)
            self._queued_publish_bytes=0

    def _tcp_send(self, data: bytes):
        attempts: int = 0
        ready_to_send: bool = False
        while not ready_to_send:
            if attempts > 5:
                raise Exception('error initiating tcp send')
            attempts = attempts + 1
            self._send_at_cmd('CIPSEND=' + str(len(data)), wait_time=0)
            ready_to_send = self._await_serial_response(b'>')
            if attempts:
                time.sleep(1)
        self._ser.write(data)
        if not self._await_serial_response(b"SEND OK"):
            raise Exception("error on TCP send")


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
        self._at_disable_echo_sim800c()
        self._tcp_connect_sim800c(host, port, tls=tls)
        self._mqtt_keepalive = keep_alive
        connect = mqtt_codec.packet.MqttConnect(client_id=client_id, clean_session=False, keep_alive=30, username=username, password=password)
        with BytesIO() as f:
            connect.encode(f)
            buf = f.getvalue()
            self._tcp_send(buf)
            connack_packet = self._ser.read(6)[-3:]
            self._log.debug("Got connack: " + str(connack_packet))
            self._process_connack(connack_packet)
            if(keep_alive is not None):
                schedule.every(math.ceil(keep_alive/2)).seconds.do(self._mqtt_ping)
            self._log.info('Sucessfully connected to MQTT broker.')

    def publish(self, topic: str, message: bytearray, dupe: bool = False, qos: int = 0, retain: bool = False):
        """ Publish a message to a MQTT topic

        Args:
            topic (str)
            message (bytearray)
            dupe (bool, optional): Defaults to False.
            qos (int, optional): Defaults to 0.
            retain (bool, optional): Defaults to False.
        """
        publish = mqtt_codec.packet.MqttPublish(5, topic, message.encode(), dupe, qos, retain)
        with BytesIO() as f:
            num_bytes_written = publish.encode(f)
            buf = f.getvalue()
            self._publish_jobs.append(buf)
            self._queued_publish_bytes = self._queued_publish_bytes + num_bytes_written

    def subscribe(self, topic: str, handler: Callable[[str,bytes],None]):
        """ Subscribe to a MQTT topic

        Args:
            topic (str)
            handler (Callable[[str,bytes],None]): This function will be called when a message arrives on this topic
              > The function should accept two arguments: topic (str) and message (bytes)

        Raises:
            MQTTPacketException: Raised if the server does not send back a valid subscription acknowledgement
            packet. 

            More: http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718068
        """
        subscribe = mqtt_codec.packet.MqttSubscribe(3, [mqtt_codec.packet.MqttTopic(topic, 0)])
        with BytesIO() as f:
            subscribe.encode(f)
            buf = f.getvalue()
            self._tcp_send(buf)
            res = self._ser.read(7)[-5:]
            if res[0] & MQTT_PKT_TYPE_MASK == MQTT_SUBACK:
                raise MQTTPacketException('subscription error: invalid suback header')
            self._log.debug('suback packet: ' + str(res))
            self._log.debug('Subscribed to topic: "' + topic + '"')
            self._sub_handlers[topic] = handler

    def loop(self):
        while True:
            schedule.run_pending()
            self._check_for_publish_messages()
            self._send_queued_publish_jobs()