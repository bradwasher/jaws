from gps import *
import time
import threading
import json

#adapted from
#http://www.danmandle.com/blog/getting-gpsd-to-work-with-python/

class GpsPoller(threading.Thread):
    def __init__(self, poll_interval = 1):
        threading.Thread.__init__(self)

        global gpsd  # bring it in scope
        gpsd = gps(mode=WATCH_NEWSTYLE)  # starting the stream of info
        self.poll_interval = poll_interval
        self.last_location = None
        self._running = True  # setting the thread running to true

    def get_location(self):
        return self.last_location

    def run(self):
        """
        overrides the threading.Thread run method
        """
        while self._running:
            report = gpsd.next()  # this will continue to loop and grab EACH set of gpsd info to clear the buffer
            if report['class'] == 'TPV':
                location = vars(report)
                self.last_location = location
            time.sleep(self.poll_interval)

    def stop(self):
        self._running = False
