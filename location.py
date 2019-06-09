
import gpspoller
import time

class Location:

    def __init__(self, mode, stat_lat=0, stat_lon=0):
        self.mode = mode
        if(self.mode == 'static'):
            self.static_latitude = stat_lat
            self.static_longitude = stat_lon
            self.gps_poll = None
        else:
            self.static_latitude = None
            self.static_longitude = None
            self.last_dynamic_location = {}
            self.gpsp = gpspoller.GpsPoller()
            self.gpsp.start()




    def get_location(self):
        if self.mode == 'static':
            location = {'location_mode': 'static', 'latitude': self.static_latitude, 'longitude':  self.static_longitude}
        else:
            location = self.get_dynamic_location()

        return location


    def get_dynamic_location(self):
        try:
            loc = self.gpsp.get_location()
            loc['location_mode'] = 'dynamic'
            self.last_dynamic_location = loc
            return loc
        except:
            self.last_dynamic_location['location_status'] = 'gps-error'
            return self.last_dynamic_location



