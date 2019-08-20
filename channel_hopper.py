import os
import time
import threading

class ChannelHopper(threading.Thread):
    def __init__(self, interface, dwell_time):
        self._running = True
        self.interface = interface
        self.dwell_time = float(dwell_time)


    def run(self):
        channel = 1
        while self._running:
            #os.system(f"iwconfig {interface} channel {channel}")
            time.sleep(self.dwell_time)
            if channel == 1:
                channel = 6
            elif channel == 6:
                channel = 11
            else:
                channel = 1
            print(f"channel {channel}")

    def stop(self):
        self._running = False