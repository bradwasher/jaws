import requests
import threading
import json
import time
from datetime import datetime

class WebAPI(threading.Thread):
    def __init__(self, post_url, jwt="", chunk_size=20, max_checkin_attempts=5, interval=5):
        threading.Thread.__init__(self)
        self._running = True

        self.post_url = post_url
        self.jwt = jwt
        self.chunk_size = chunk_size
        self.max_checkin_attempts = max_checkin_attempts
        self.interval = interval
        self.queue = []

    def run(self):
        while self._running:
            self._process_queue()
            time.sleep(self.interval)

    def stop(self, process_queue=True):
        if process_queue:
            self._process_queue()

        self._running = False

    def check_in(self, settings):
        settings["record_type"] = "checkin"
        settings["sensor_utc"] = self.time_stamp()

        results = self._post(self.post_url, settings)
        counter = 1

        while results.status_code != 200:
            if counter == self.max_checkin_attempts:
                return {'status':'failed'}
            print("Unable to successfully contact collection point - {0} {1}. Trying again....".format(results.status_code, results.text))
            time.sleep(5)
            results = self._post(self.post_url, checkin)
            counter += 1

        if "mode" in settings.keys() and settings["mode"] == 'target-list':
            tl = results.json()
            tl['status'] = 'success'
            return tl

        return {'status':'success'}

    def queue_record(self, record):
        self.queue.append(record)


    def _post(self, url, json_data):
        headers = {'Authorization': 'Bearer {}'.format(self.jwt)}
        result = requests.post(url, json=json_data, verify=False, headers=headers)

        return result


    def _process_queue(self):
        count = len(self.queue)

        if count > 0:
            records = self.queue[0:count]
            del self.queue[0:count]

            print("processing records: {0}".format(len(records)))
            chunks = self._get_chunks(records, self.chunk_size)
            for chunk in chunks:
                record = {}
                record["records"] = chunk
                response = self._post(self.post_url, record)
                print('{0} - {1}'.format(response.status_code, response.text))
                #if failure then push back on the queue?

    @staticmethod
    def _get_chunks(lst, n):
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

    @staticmethod
    def time_stamp():
        #return f'{datetime.utcnow():%Y-%m-%d %H:%M:%S%z}'
        return str(datetime.utcnow())

