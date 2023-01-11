import os
import time
import math
import serial
import schedule
import configparser
import mqtt_codec.io
import mqtt_codec.packet

from enum import Enum
from io import BytesIO
from datetime import datetime
from functools import total_ordering

config = configparser.ConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__)) + '/config.ini')

#Constants used to recognize MQTT packets
MQTT_PKT_TYPE_MASK = 0xF0
MQTT_PUBLISH = 0x30
MQTT_PINGREQ = b"\xc0\0"
MQTT_PINGRESP = 0xD0
MQTT_SUB = b"\x82"
MQTT_UNSUB = b"\xA2"
MQTT_DISCONNECT = b"\xe0\0"

class WirelessChip(Enum):
    SIM800C = 1

class CMDType(Enum):
    AT = 1
    BYTES = 2

@total_ordering
class LogLevel(Enum):
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4
    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented

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

    def __init__(self, 
    log_level: LogLevel = LogLevel.INFO, 
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
        self._log_level = log_level

    def _log(self, level:LogLevel=LogLevel.INFO, component: str = 'main', message = ''):
        """ Logger - see LogLevel enum above. Recommended to run with default log level of INFO to avoid large logfiles on edge devices

        Args:
            level (LogLevel, optional): [description]. Defaults to LogLevel.INFO.
            component (str, optional): [description]. Defaults to 'main'.
            message (any, optional): [description]. Defaults to ''.
        """
        if(level >= self._log_level):
            print(str(datetime.utcnow()) + ' [' + str(level) + '] ' + str(message))

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

    def _send_at_cmd(self, data: str, read: bool = True):
        """ Send AT command to cellular module

        Args:
            data (str): Raw, unformatted command text
            read (bool, optional): If set to true, the command will read from the bus, even if it is not printing to log. Defaults to True.
        """
        self._ser.write(self._format_at_cmd_sim800c(data))
        time.sleep(1)
        if read:
            data = self._ser.read(14816)
            self._log(level=LogLevel.DEBUG, message=data)

    def _send_cmd_await_response(self, data, response_len: int, initial_wait: int = 1, burn_bytes: int = None, type: CMDType = CMDType.BYTES) -> bytes:
        """ Send a command or data to the cellular module and await a response of a known length

        Args:
            data (bytes | str): Data to be written to serial bus
            response_len (int): The known response length that we will be looking for
            initial_wait (int, optional): Amount of time to wait prior to looking for the response data. Defaults to 1.
            burn_bytes (int, optional): How many bytes to burn until capturing the desired response. Defaults to None.
            type (CMDType, optional): Defaults to CMDType.BYTES.

        Returns:
            bytes: This is the best effort captured response, which should then be validated by the requesting function
        """
        if(type is CMDType.BYTES):
            self._ser.write(data)
        elif(type is CMDType.AT):
            self._ser.write(self._format_at_cmd_sim800c(data))
        if(initial_wait is not None):
            time.sleep(initial_wait)
        if(burn_bytes is not None):
            self._log(level=LogLevel.DEBUG, message = 'Read ' + str(burn_bytes) + ' bytes before response: ')
            self._log(level=LogLevel.DEBUG, message = self._ser.read(burn_bytes))
        return self._ser.read(response_len)

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
        self._log(message = 'Establishing TCP connection...')
        self._send_at_cmd('CIPCLOSE')
        self._send_at_cmd('CIPSHUT')
        self._send_at_cmd('CGATT?')
        self._send_at_cmd('CSTT="{}"'.format(self._cell_apn))
        self._send_at_cmd('CIICR')
        self._send_at_cmd('CIFSR')
        if tls:
            self._send_at_cmd('CIPSSL=1')
        response = self._send_cmd_await_response('CIPSTART="TCP","' + host + '",' + str(port), 10, burn_bytes=8, type=CMDType.AT)
        if response != b'CONNECT OK':
            raise Exception('could not establish tcp connection with server')
        self._log(message = 'TCP connection established.')

    def _process_connack(self, packet: bytearray):
        """ Process the MQTT connack packet - see more here: 
        http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718033

        Args:
            packet (bytearray): Raw connack packet to be validated

        Raises:
            MQTTPacketException
            MQTTServerException
        """
        if(len(packet) is not 3):
            raise MQTTPacketException('connack error: invalid packet length')
        if(packet[0] is not 0x02):
            raise MQTTPacketException('connack error: invalid fixed header in packet')
        if(packet[2] is not 0x00):
            raise MQTTServerException('connack error: server refused connection with error code: ' + str(packet[2]))
        self._log(level=LogLevel.DEBUG, message = 'connack packet: ' + str(packet))

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
        self._log(message = 'Attempting connection to MQTT broker...')
        self._at_disable_echo_sim800c()
        self._tcp_connect_sim800c(host, port, tls=tls)
        self._mqtt_keepalive = keep_alive
        connect = mqtt_codec.packet.MqttConnect(client_id=client_id, clean_session=False, keep_alive=30, username=username, password=password)
        with BytesIO() as f:
            num_bytes_written = connect.encode(f)
            buf = f.getvalue()
            self._send_at_cmd('CIPSEND=' + str(num_bytes_written))
            connack_packet = self._send_cmd_await_response(buf,3,burn_bytes=12)
            try:
                self._process_connack(connack_packet)
                if(keep_alive is not None):
                    schedule.every(math.ceil(keep_alive/2)).seconds.do(self._mqtt_ping)
                self._log(message = 'Sucessfully connected to MQTT broker.')
            except MQTTPacketException:
                # if there was a problem reading the connack packet, reconnect
                time.sleep(5)
                self._connect(client_id, host, port, username, password, keep_alive)

    def _get_mqtt_ping_msg(self) -> MQTT_PINGRESP | None:
        """ Find the MQTT PINGRESP packet in order to validate a ping response
        """
        res = self._ser.read(1)
        if res in [None, b"", b"\x00"]:
            return None
        if res[0] & MQTT_PKT_TYPE_MASK == MQTT_PINGRESP:
            return MQTT_PINGRESP

    def _mqtt_ping(self):
        """ Ping the MQTT broker

        Raises:
            Exception: Raised if no valid ping response is received from the MQTT broker
        """
        self._send_at_cmd('CIPSEND=2')
        self._ser.write(b'\xc0\x00')
        ping_timeout = self._mqtt_keepalive
        stamp = time.monotonic()
        res = None
        while res != MQTT_PINGRESP:
            res = self._get_mqtt_ping_msg()
            if res:
                self._log(level=LogLevel.DEBUG, message = 'mqtt ping got response from broker')
            if time.monotonic() - stamp > ping_timeout:
                raise Exception("mqtt ping did not get response from broker")

    def publish(self, topic: str, message: bytearray, dupe: bool = False, qos: int = 0, retain: bool = False):
        """ Publish a message to a MQTT topic

        Args:
            topic (str)
            message (bytearray)
            dupe (bool, optional): Defaults to False.
            qos (int, optional): Defaults to 0.
            retain (bool, optional): Defaults to False.
        """
        publish = mqtt_codec.packet.MqttPublish(3, topic, message.encode(), dupe, qos, retain)
        with BytesIO() as f:
            num_bytes_written = publish.encode(f)
            buf = f.getvalue()
            self._send_at_cmd('CIPSEND=' + str(num_bytes_written))
            self._ser.write(buf)

    def subscribe(self, topic: str):
        """ Subscribe to a MQTT topic

        Args:
            topic (str)

        Raises:
            MQTTPacketException: Raised if the server does not send back a valid subscription acknowledgement
            packet. 

            More: http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718068
        """
        subscribe = mqtt_codec.packet.MqttSubscribe(3, [mqtt_codec.packet.MqttTopic(topic, 0)])
        with BytesIO() as f:
            num_bytes_written = subscribe.encode(f)
            buf = f.getvalue()
            self._send_at_cmd('CIPSEND=' + str(num_bytes_written))
            res = self._send_cmd_await_response(buf,5,burn_bytes=11)
            if(len(res) is not 5):
                raise MQTTPacketException('subscription error: invalid packet length')
            if(res[0] is not 0x90):
                raise MQTTPacketException('subscription error: invalid fixed header')
            self._log(level=LogLevel.DEBUG, message = 'suback packet: ' + str(res))
            self._log(level=LogLevel.DEBUG, message = 'Subscribed to topic: "' + topic + '"')

    def _get_remaining_len(self) -> int:
        """ Get the remaining length in the publish packet using some bitmath.

        Returns:
            int
        """
        n = 0
        sh = 0
        b = bytearray(1)
        while True:
            b = self._ser.read(1)[0]
            n |= (b & 0x7F) << sh
            if not b & 0x80:
                return n
            sh += 7

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
            self._log(level=LogLevel.DEBUG, message = 'got message for topic: ' + topic )
            self._log(level=LogLevel.DEBUG, message = 'payload: ' + msg )

    def loop(self):
        while True:
            schedule.run_pending()
            self._check_for_publish_messages()
            time.sleep(.05)