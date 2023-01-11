import schedule

from datetime import datetime
from cellmqtt import CellMQTT, LogLevel, WirelessChip

cmqtt = CellMQTT(cell_chip=WirelessChip.SIM800C, log_level=LogLevel.DEBUG)
cmqtt.connect()

def handle_test(topic: str, message: bytes):
    print('------ GOT MSG FROM TOPIC: ' + topic + '! ------')
    print(str(message, 'utf-8'))
    print('------ END OF MESSAGE ------')

cmqtt.subscribe('ext/test', handle_test)

def publish_demo():
    cmqtt.publish('ext/test/date', str(datetime.utcnow()))

schedule.every(40).seconds.do(publish_demo)

cmqtt.loop()