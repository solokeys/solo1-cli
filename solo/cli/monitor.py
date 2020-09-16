# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import sys
import time

import click
import serial


@click.command()
@click.argument("serial_port")
def monitor(serial_port):
    """Reads Solo Hacker serial output from USB serial port SERIAL_PORT.

    SERIAL-PORT is something like /dev/ttyACM0 or COM10.
    Automatically reconnects. Baud rate is 115200.
    """

    ser = None

    def reconnect():
        while True:
            time.sleep(0.02)
            try:
                ser = serial.Serial(serial_port, 115200, timeout=0.05)
                return ser
            except serial.SerialException:
                pass

    while True:
        try:
            if ser is None:
                ser = serial.Serial(serial_port, 115200, timeout=0.05)
            data = ser.read(1)
            sys.stdout.buffer.write(data)
            sys.stdout.flush()
        except serial.SerialException:
            if ser is not None:
                ser.close()
            print(f"reconnecting {serial_port}...")
            ser = reconnect()
            print("done")
