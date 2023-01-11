import os
import time
import math
import serial
import schedule
import mqtt_codec.io
import configparser
import mqtt_codec.packet

from enum import Enum
from io import BytesIO
from datetime import datetime
from functools import total_ordering

config = configparser.ConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__)) + '/config.ini')

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
    pass

class MQTTServerException(Exception):
    pass

class CellMQTT:

    def __init__(self, 
    log_level = LogLevel.INFO, 
    serial_path = config['SERIAL_PORT']['SerialPath'], 
    baud_rate=config['SERIAL_PORT']['BaudRate'], 
    timeout=config['SERIAL_PORT']['Timeout'], 
    cell_chip = WirelessChip.SIM800C, 
    cell_apn = config['CELLULAR']['APN']):
        self._ser = serial.Serial(serial_path, baud_rate, timeout=int(timeout))
        self._cell_chip = cell_chip
        self._cell_apn = cell_apn
        self._log_level = log_level

    def _log(self, level=LogLevel.INFO, component = 'main', message = ''):
        if(level >= self._log_level):
            print(str(datetime.utcnow()) + ' [' + str(level) + '] ' + str(message))

    def _format_at_cmd(self, data):
        data = 'AT+' + data + '\r\n'
        return data.encode()

    def _at_disable_echo(self):
        self._ser.write('ATE0\r\n'.encode())

    def _send_at_cmd(self, data, read=True):
        self._ser.write(self._format_at_cmd(data))
        time.sleep(1)
        if read:
            data = self._ser.read(14816)
            self._log(level=LogLevel.DEBUG, message=data)

    def _send_cmd_await_response(self, data, response_len, initial_wait=1, burn_bytes=None, type=CMDType.BYTES):
        if(type is CMDType.BYTES):
            self._ser.write(data)
        elif(type is CMDType.AT):
            self._ser.write(self._format_at_cmd(data))
        if(initial_wait is not None):
            time.sleep(initial_wait)
        if(burn_bytes is not None):
            self._log(level=LogLevel.DEBUG, message = 'Read ' + str(burn_bytes) + ' bytes before response: ')
            self._log(level=LogLevel.DEBUG, message = self._ser.read(burn_bytes))
        return self._ser.read(response_len)

    def _tcp_connect(self, host, port, tls=False):
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

    def _process_connack(self, packet):
        if(len(packet) is not 3):
            raise MQTTPacketException('connack error: invalid packet length')
        if(packet[0] is not 0x02):
            raise MQTTPacketException('connack error: invalid fixed header in packet')
        if(packet[2] is not 0x00):
            raise MQTTServerException('connack error: server refused connection with error code: ' + str(packet[2]))
        self._log(level=LogLevel.DEBUG, message = 'connack packet: ' + str(packet))

    def connect(self, client_id = config['MQTT_BROKER']['MQTTClientID'], host = config['MQTT_BROKER']['MQTTHost'], port = config['MQTT_BROKER']['MQTTPort'], username = config['MQTT_BROKER']['MQTTUsername'], password = config['MQTT_BROKER']['MQTTPassword'], keep_alive=int(config['MQTT_BROKER']['MQTTKeepAlive']), tls=config['MQTT_BROKER']['MQTTSSL']):
        self._log(message = 'Attempting connection to MQTT broker...')
        self._at_disable_echo()
        self._tcp_connect(host, port, tls=tls)
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

    def _get_mqtt_ping_msg(self):
        res = self._ser.read(1)
        if res in [None, b"", b"\x00"]:
            return None
        if res[0] & MQTT_PKT_TYPE_MASK == MQTT_PINGRESP:
            return MQTT_PINGRESP

    def _mqtt_ping(self):
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

    def publish(self, topic,message, dupe=False, qos=0, retain=False):
        publish = mqtt_codec.packet.MqttPublish(3, topic, message.encode(), dupe, qos, retain)
        with BytesIO() as f:
            num_bytes_written = publish.encode(f)
            buf = f.getvalue()
            self._send_at_cmd('CIPSEND=' + str(num_bytes_written))
            self._ser.write(buf)

    def subscribe(self, topic):
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

    def _get_remaining_len(self):
        n = 0
        sh = 0
        b = bytearray(1)
        while True:
            b = self._ser.read(1)[0]
            n |= (b & 0x7F) << sh
            if not b & 0x80:
                return n
            sh += 7

    def _check_for_publish_messages(self):
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