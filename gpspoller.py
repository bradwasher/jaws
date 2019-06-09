from gps import *
import time
import threading
import json

#adapted from
#http://www.danmandle.com/blog/getting-gpsd-to-work-with-python/

class GpsPoller(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

        global gpsd  # bring it in scope
        gpsd = gps(mode=WATCH_NEWSTYLE)  # starting the stream of info
        self.last_location = None
        self.running = True  # setting the thread running to true

    def get_location(self):
        return self.last_location

    def run(self):

        while True:
            report = gpsd.next()  # this will continue to loop and grab EACH set of gpsd info to clear the buffer
            if(report['class'] == 'TPV'):
                location = vars(report)
                self.last_location = location
            time.sleep(1)