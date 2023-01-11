# CellMQTT

Lightweight IoT MQTT library for mobile network chips (so far just SIM800c)

## Overview

This MQTT client library was born out of the seeming lack of documentation/support for the SIM800c GPRS chip. As of this writing, it is now January 2023 and GSM/GPRS is mostly phased out, and the SIM800c chip has been left in the dust - but it is still cheap and widely available, so hopefully this helps someone else get started.

I also tried to make the API as chip-agnostic as possible, so while there is only one implementation now, for the `SIM800c`, please feel free to roll your own for another chip and make a PR.

## Getting Started

### Configuration

There is a `config-sample.ini` file which should be renamed to `config.ini`. These values can also be overridden when initializing the `CellMQTT` class in your program.

## Acknowledgements

There were a lot of great resources that helped me understand the workings of GSM/GPRS chips, serial connections, MQTT protocols, and more. Some are more relevant, some less, but all of the following were extremely helpful to me:

* [Adafruit CircuitPython_MiniMQTT](https://github.com/adafruit/Adafruit_CircuitPython_MiniMQTT/)
  This client library from Adafruit was really helpful to get an understanding of how MQTT clients work on a lower level.

* [MQTT Protocol tutorial using SIM900/SIM800 modules – MQTT over TCP](https://www.raviyp.com/mqtt-protocol-tutorial-using-sim900-sim800-modules-mqtt-over-tcp/) - This blog post and associated YouTube video from **Ravi Pujar** was what gave me the initial boost of confidence that I could actually get this done with the `SIM800c` module I had on hand. He does explain the underlying concepts, but there is definitely not much to copy/paste and get going here.

* [WaveShare Wiki - SIM800C GSM/GPRS HAT](https://www.waveshare.com/wiki/SIM800C_GSM/GPRS_HAT) - WaveShare, who makes the module that I have has a pretty decent documentation page.

* [usim800 python library](https://github.com/Bhagyarsh/usim800/tree/master/usim800) - This library was what I was initially going to use to simply make HTTP requests - but it turned out to not really meet my needs - playing around with @Bhagyarsh library helped me gain a lot of understanding of the underlying AT commands for the SIM800c

* [MQTT Version 3.1.1 protocol docs](http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) - This is probably the single most important resource for understanding how MQTT actually works

* [mqtt-codec python library](https://github.com/kcallin/mqtt-codec) - Last, but absolutely not least, is the `mqtt-codec` library. Until I found this it was an absolute uphill battle for me to get MQTT packets correctly formed.