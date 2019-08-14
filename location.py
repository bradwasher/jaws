import gps_poller
import time
import threading

class Location:

    def __init__(self, mode, logger, static_lat=0, static_lon=0):
        print("location here!")
        self.mode = mode
        if self.mode == 'static':
            self.static_latitude = static_lat
            self.static_longitude = static_lon
            self.gps_poll = None
        else:
            self.static_latitude = None
            self.static_longitude = None
            self.last_dynamic_location = {}
            self.gpsp = gps_poller.GpsPoller()

    def run(self):
        if self.mode == "dynamic":
            threading.Thread.__init__(self.gpsp)
            self.gpsp.start()

    def get_location(self):
        if self.mode == 'static':
            location = {'location_mode': 'static', 'latitude': self.static_latitude, 'longitude':  self.static_longitude}
        else:
            location = self._get_dynamic_location()

        return location

    def _get_dynamic_location(self):
        try:
            loc = self.gpsp.get_location()
            loc['location_mode'] = 'dynamic'
            self.last_dynamic_location = loc
            return loc
        except:
            self.last_dynamic_location['location_status'] = 'gps-error'
            return self.last_dynamic_location

    def stop_polling(self):
        if self.mode == "dynamic":
            self.gpsp.stop()
            self.gpsp.join()



