import time
import channel_hopper
import threading

class MonitorInterface():
    def __init__(self, interface, mode="hop", channel_lock=6, dwell_time=.5):
        self.interface = interface
        self.mode = mode
        self.channel_lock = channel_lock
        self.dwell_time = dwell_time

        if mode != "lock" and mode != "hop":
            raise ValueError("Invalid network interface mode specified")

        if mode == "lock" and channel_lock not in range(1,12):
            raise ValueError("Channel must be specified (1-12) if interface is set to channel lock mode")

        if self.mode == "hop":
            self.hopper = channel_hopper.ChannelHopper(self.interface, self.dwell_time)
            #self.hopper.start()

    def run(self):
        if self.mode == "lock":
            #os.system(f"iwconfig {interface} channel {channel}")
            pass
        else:
            #initialize object; not sure why this isn't happening when it's created...
            threading.Thread.__init__(self.hopper)
            #super(channel_hopper.ChannelHopper, self.hopper).__init__()
            self.hopper.start()

    def stop_hopping(self):
        if self.mode == "hop":
            self.hopper.stop()
            self.hopper.join()

