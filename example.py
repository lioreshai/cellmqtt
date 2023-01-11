import schedule

from datetime import datetime
from cellmqtt import CellMQTT, LogLevel, WirelessChip


cmqtt = CellMQTT(cell_chip=WirelessChip.SIM800C, log_level=LogLevel.DEBUG)
cmqtt.connect()

cmqtt.subscribe('ext/test')

def publish_demo():
    cmqtt.publish('ext/test/date', str(datetime.utcnow()))

schedule.every(40).seconds.do(publish_demo)

cmqtt.loop()