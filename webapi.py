import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
import json
from datetime import datetime
import time
import threading


class WebAPI:

    def __init__(self, command_line_args):

        self.args = command_line_args
        self.cpip = self.args['collection_point_ip']
        self.sensor_id = self.args['sensor_id']
        self.batch_id = self.args['batch_id']
        self.batch_description = self.args['batch_description']
        self.gps_coordinates = self.args['gps_coordinates']
        self.post_url = "https://{0}/api/record/createmongo.php".format(self.cpip)
        #self.post_many_url = "https://{0}/api/record/createmany.php".format(self.cpip)
        self.monitor_mode = self.args['monitor_mode']
        self.record_queue = []
        self.chunk_size = 20
        self.max_checkin_attempts = 5
        self.jwt = self.args['json_web_token']
        if self.args['alert_interval'] is not None:
            self.alert_interval = self.args['alert_interval']
        else:
            self.alert_interval = 5

        print('Setting alert interval: {0}'.format(self.alert_interval))

        self.start_alert_interval()


    def check_in(self):
        checkin = self.args
        checkin['record_type'] = 'checkin'
        checkin['sensor_utc'] = self.time_stamp()

        results = self.post(self.post_url, checkin)
        counter = 1

        while results.status_code != 201:
            if counter == self.max_checkin_attempts:
                return {'status':'failed'}
            print("Unable to successfully contact collection point - {0} {1}. Trying again....".format(results.status_code, results.text))
            time.sleep(5)
            results = self.post(self.post_url, checkin)
            counter += 1

        if self.monitor_mode == 'target-list':
            tl = results.json()
            tl['status'] = 'success'
            return tl

        return {'status':'success'}

    def time_stamp(self):
        return f'{datetime.utcnow():%Y-%m-%d %H:%M:%S%z}'

    def post(self, url, json):


        headers = {'Authorization': 'Bearer {}'.format(self.jwt)}
        result = requests.post(url, json=json, verify=False, headers=headers)

        return result

    def queue_record(self, record):
        self.record_queue.append(record)

    def process_queue(self):
        print('Beginning alert queue...')
        while True:
            if len(self.record_queue) > 0:
                process_queue = self.record_queue
                self.record_queue = []

                print('processing records: {0}'.format(len(process_queue)))
                chunks = self.get_chunks(process_queue, self.chunk_size)
                #chunked = process_queue
                for chunk in chunks:
                    record = {}
                    record['records'] = chunk
                    #print('json: {0}'.format(record))
                    response = self.post(self.post_url, record)
                    print('{0} - {1}'.format(response.status_code, response.text))
                    #if failure then push back on the queue

            time.sleep(int(self.alert_interval))

    def start_alert_interval(self):
        thread = threading.Thread(target=self.process_queue, name="process_queue")
        thread.daemon = True
        thread.start()

    def get_chunks(self, lst, n):
        groups = []
        group = []
        for item in lst:
            if len(group) >= n:
                groups.append(group)
                group = []
            group.append(item)

        if len(group) > 0:
            groups.append(group)

        return groups

'''
All posts to the collection point go to the same URI /api/record/create
the collection point, if necessary can then determine whether to split them 
apart and redirect them to different repositories

checkin record example
{
	"record_type": "checkin",
	"sensor_id": "8b259873-1311-4ab9-8dbf-662f2d0f958b",
	"collection_point_ip": "192.168.0.1",
	"monitor_mode": null,
	"target_list_id": 1,
	"alert_interval": null,
	"monitor_interface": "mon0",
	"channel_lock": "9",
	"tor_port": null,
	"gps_coordinates": "35.173204,-79.424254",
	"batch_id": null,
	"batch_description": null,
	"sensor_utc": "2019-02-23 15:07:53"
} 
instruction return -- future use to overwrite command line args, 
but for now just used to return a target list of MAC addresses
{
	"sensor_id": "8b259873-1311-4ab9-8dbf-662f2d0f958b",
	"target_list_id": 1,
	"target_list": [
		"deadbeef0001",
		"deadbeef0002",
		"deadbeef0003"
	]
}

{"target_list_id":"1","targets":["24:79:2a:3e:c5:38","b4:e6:2a:48:d1:1c"]}

target hit
{
	"record_type": "target-hit",
	"sensor_id": "8b259873-1311-4ab9-8dbf-662f2d0f958b",
	"sensor_timestamp": "2019-02-25 03:01:42",
	"sensor_lat": "35.173204",
	"sensor_lon": "-79.424254",
	"channel": 2412,
	"dBm": -15,
	"type": 1,
	"type_desc": "Control",
	"subtype": 13,
	"subtype_desc": "ACK",
	"ssid": "",
	"src_mac": "00:00:00:00:00:00",
	"dst_mac": "b0:72:bf:fa:6a:c4",
	"bssid": "00:00:00:00:00:00",
	"target_hit": {
		"target": "b072bffa6ac4"
	}
}





'''