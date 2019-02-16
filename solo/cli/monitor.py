import sys

import click
import serial


@click.command()
@click.argument("serial_port")
def monitor(serial_port):
    """Reads Solo Hacker serial output from USB serial port SERIAL_PORT.

    SERIAL-PORT is something like /dev/ttyACM0 or COM10.
    Automatically reconnects. Baud rate is 115200.
    """

    import serial

    ser = serial.Serial(serial_port, 115200, timeout=0.05)

    def reconnect():
        while True:
            time.sleep(0.02)
            try:
                ser = serial.Serial(port, 115200, timeout=0.05)
                return ser
            except serial.SerialException:
                pass

    while True:
        try:
            data = ser.read(1)
        except serial.SerialException:
            print("reconnecting...")
            ser = reconnect()
            print("done")
        sys.stdout.buffer.write(data)
        sys.stdout.flush()
