#! /usr/bin/python3

from scapy.all import *
import threading
import os, time
import random
import argparse
from uuid import UUID
import sys
import socket
import subprocess
import netaddr
import webapi
import location
import json
from datetime import datetime

'''
The sensor script accepts the following command line switches:
    -s  --sensor-id                 =>  unique identifier of the sensor that is passed to the collection point with each record
    -c  --collection-point-ip       =>  ip where records are posted
    -t  --target-list-id            =>  identifier of MAC target list to pull down from collection point at first check-in
    -m  --monitor-mode              =>  monitor mode of sensor; can be either target-list, all-selectors, or all-events
    -a  --alert-interval            =>  interval in seconds between when records (if they exist) are posted to collection point; if 0 then post immediately
    -i  --monitor-interface         =>  device the sensor is using to monitor
    -l --channel-lock               =>  channel to lock onto; default is to hop from 1 to 6 to 11    
    -p  --tor-port                  =>  port to route traffic through; default is to not use TOR
    -g  --gps-coordinates           =>  if value is 'dynamic' then attempt to get location from gps device; otherwise input static coordinates of sensor (eg '1.234,5.678')
    -b  --batch-id                  =>  an identifier for this batch of collection
    -d  --batch-description         =>  a description for this batch of collection
'''

def main():

    #get and validate command line arguments
    global ARGS
    ARGS = get_args()

    print('Initializing sensor...')

    #initialize other globals
    global TARGETS
    TARGETS = []

    global THRESHOLD
    THRESHOLD = {}

    global LOCATION
    if ARGS['gps_coordinates'] == 'dynamic':
        LOCATION = location.Location('dynamic')
    else:
        lat,lon = ARGS['gps_coordinates'].split(',')
        LOCATION = location.Location('static',lat,lon  )


    #check in with collection point
    print('Checking in with collection point...')
    global API
    API = webapi.WebAPI(ARGS)
    checkin = API.check_in()
    if checkin['status'] == 'success':
        #set target list if available
        if 'targets' in checkin and len(checkin['targets']) > 0:
            TARGETS = [x.lower().replace(':','') for x in checkin['targets']]
        elif 'targets' in checkin and len(TARGETS) == 0:
            sys.exit("Exiting - No targets in target dekt {0}".format(ARGS['target_list_id']))

    else:
        #unable to check in with collection point; exiting
        sys.exit("Exiting - Unable to check in with collection point at {0}".format(ARGS['collection_point_ip']))

    #set channel mode
    if ARGS['channel_lock'] is None:
        start_channel_hop(ARGS['monitor_interface'])
    else:
        channel_lock(ARGS['monitor_interface'], ARGS['channel_lock'])

    print('Starting collection...')


    sniff(iface=ARGS['monitor_interface'], prn=packet_handler, store=0, count=0)


def packet_handler(pkt):
    timestamp = datetime.utcnow()
    record = {}

    #if the collection mode is 'target-list' then identify if either the src_mac or dst_mac
    # are in the target deck.  If so, then also check to see if the target is within the
    # threshold since a packet was last processed from it.  Since target-list mode is generally
    # used just to identify targets within range and simple metrics, most packets are dropped
    # so that the web server and database aren't inundated with posts. The exception is that
    # EAPOL and Management records are always captured
    if ARGS['monitor_mode'] == 'target-list':
        target = target_found(pkt)
        if target and (pkt.haslayer(EAPOL) or pkt.type == 0 or within_threshold(target, timestamp, pkt)):
            record = create_record(pkt, timestamp)
            record['record_type'] = 'target-hit'
            record['target_hit'] = {}
            record['target_hit']['target'] = target

    elif ARGS['monitor_mode'] == 'all-selectors':
        record = create_record(pkt, timestamp)
        record['record_type'] = 'selector-collect'

        process = False
        for i in record['macs']:
            if pkt.haslayer(EAPOL) or within_threshold(i, timestamp, pkt):
                process = True
        if not process:
            record = None



    #if the frame has EAPOL, get the raw data
    if record and pkt.haslayer(EAPOL):
        eapol = []
        for x in pkt.getlayer(Raw):
            eapol.append(x.load.hex())
        if len(eapol) > 0:
            record['eapol'] = ''.join(eapol)

    if record:
        API.queue_record(record)

def create_record(pkt, timestamp):

    #depending on the interface, the header can be
    #either in the Do11 layer or the Do11FCS layer
    header = object
    if Dot11 in pkt:
        header = pkt.getlayer(Dot11)
    elif Dot11FCS in pkt:
        header = pkt.getlayer(Dot11FCS)

    macs = set()

    dst_mac = None
    if hasattr(header,'addr1') and header.addr1 is not None:
        dst_mac = header.addr1.lower().replace(':','')
        macs.add(dst_mac)

    src_mac = None
    if hasattr(header, 'addr2') and header.addr2 is not None:
        src_mac = header.addr2.lower().replace(':','')
        macs.add(src_mac)

    bssid = None
    if hasattr(header, 'addr3') and header.addr3 is not None:
        bssid = header.addr3.lower().replace(':','')
        macs.add(bssid)

    type = None
    if hasattr(header, 'type'):
        type = header.type

    subtype = None
    if hasattr(header, 'subtype'):
        subtype = header.subtype

    ssid = None
    try:
        ssid = [x.info.decode() for x in pkt[Dot11][Dot11Elt] if x.ID == 0][0]
    except:
        pass

    dBm = pkt[RadioTap].dBm_AntSignal
    channel = pkt[RadioTap].Channel

    type_desc = ''
    if type == 0:
        type_desc = 'Managment'
    elif type == 1:
        type_desc = 'Control'
    elif type == 2:
        type_desc = 'Data'

    subtype_desc = ''
    if type == 0:
        if subtype == 0:
            subtype_desc = 'Association Request'
        elif subtype == 1:
            subtype_desc = 'Association Response'
        elif subtype == 2:
            subtype_desc = 'Reassociation Request'
        elif subtype == 3:
            subtype_desc = 'Reassociation Response'
        elif subtype == 4:
            subtype_desc = 'Probe Request'
        elif subtype == 5:
            subtype_desc = 'Probe Response'
        elif subtype == 8:
            subtype_desc = 'Beacon'
        elif subtype == 9:
            subtype_desc = 'ATIM'
        elif subtype == 10:
            subtype_desc = 'Disassociation'
        elif subtype == 11:
            subtype_desc = 'Authentication'
        elif subtype == 12:
            subtype_desc = 'Deauthentication'
    elif type == 1:
        if subtype == 10:
            subtype_desc = 'PS-Poll'
        elif subtype == 11:
            subtype_desc = 'RTS'
        elif subtype == 12:
            subtype_desc = 'CTS'
        elif subtype == 13:
            subtype_desc = 'ACK'
        elif subtype == 14:
            subtype_desc = 'CF End'
        elif subtype == 15:
            subtype_desc = 'CF End + CF AACK'

    record = {}

    record['sensor_id'] = ARGS['sensor_id']
    #record['sensor_timestamp'] = f'{timestamp:%Y-%m-%d %H:%M:%S%z}'
    record['sensor_timestamp'] = str(timestamp)
    record['sensor_location'] = LOCATION.get_location()
    record['channel'] = channel
    record['dBm'] = dBm
    record['type'] = type
    record['type_desc'] = type_desc
    record['subtype'] = subtype
    record['subtype_desc'] = subtype_desc
    record['ssid'] = ssid
    record['src_mac'] = src_mac
    record['dst_mac'] = dst_mac
    record['bssid'] = bssid
    record['macs'] = [x for x in list(macs) if x != 'ffffffffffff' and x != '000000000000']
    if 'batch_id' in ARGS:
        record['batch_id'] = ARGS['batch_id']


    return record

def target_found(pkt):
    header = object

    if Dot11 in pkt:
        header = pkt.getlayer(Dot11)
    elif Dot11FCS in pkt:
        header = pkt.getlayer(Dot11FCS)


    if hasattr(header, 'addr1') and header.addr1 is not None:
        addr1 = header.addr1.lower().replace(':','')
        if addr1 in TARGETS:
            return addr1

    if hasattr(header, 'addr2') and header.addr2 is not None:
        addr2 = header.addr2.lower().replace(':','')
        if addr2 in TARGETS:
            return addr2

    return False

def within_threshold(target, timestamp, pkt):
    global THRESHOLD
    allow_processing = False

    if target not in THRESHOLD:
        allow_processing = True
        THRESHOLD[target] = timestamp
    else:
        diff = timestamp - THRESHOLD[target]
        #print('diff: {0}  now {1}  --  past {2}'.format(diff.seconds, timestamp, THRESHOLD[target]))
        if diff.seconds > ARGS['target_threshold']:
            allow_processing = True
            THRESHOLD[target] = timestamp



    return allow_processing



def get_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("-s", "--sensor-id", required=True, help="uuid of the sensor that is passed to the collection point with each record")
    ap.add_argument("-c", "--collection-point-ip", required=True, help="IP address where records are posted via https")
    ap.add_argument("-m", "--monitor-mode", required=False, help="monitor mode of sensor; can be 'target-list' or 'all-selectors'")
    ap.add_argument("-t", "--target-list-id", required=False, help="integer identifier of MAC target list to retrieve when sensor first checks in")
    ap.add_argument("-o", "--target-threshold", required=False, help="time in seconds between target hit alerts in seconds; defaults to 15")
    ap.add_argument("-a", "--alert-interval", required=False, help="interval in seconds between when records are posted to collection point; default or 0 posts immediately")
    ap.add_argument("-i", "--monitor-interface", required=True, help="network interface the sensor is using to collect data" )
    ap.add_argument("-l", "--channel-lock", required=False, help="channel to lock on to for collection; default or 0 is to hop between 1, 6, and 11 every 1000 ms")
    ap.add_argument("-p", "--tor-port", required=False, help="port to route TOR traffic through if enabled; default is to use traditional routing")
    ap.add_argument("-g", "--gps-coordinates", required=True, help="if value is 'dynamic' then attempt to get location from gps device; otherwise input static coordinates of sensor (eg '1.234,5.678')")
    ap.add_argument("-b", "--batch-id", required=False, help="an identifier for this batch of collection")
    ap.add_argument("-d", "--batch-description", required=False, help="a description for this batch of collection")
    ap.add_argument("-w", "--channel-dwell", required=False, help="value in seconds to stay on a channel if in channel hopping mode; default is .5")
    ap.add_argument("-j", "--json-web-token", required=True, help="authorization token used to allow access to web api")
    args = vars(ap.parse_args())
    #print(args)

    #validate that the required args are correct

    #validate the sensor id
    try:
        UUID(args['sensor_id'], version=4)
    except ValueError:
        sys.exit("Exiting - Invalid Sensor ID: {0}".format(args['sensor_id']))

    #validate the collection point IP address
    try:
        socket.inet_aton(args['collection_point_ip'])
    except socket.error:
        sys.exit("Exiting - Invalid Collection Point IP: {0}".format(args['collection_point_ip']))


    #validate monitor mode
    if args['monitor_mode'] is not None and (args['monitor_mode'] != 'target-list' and args['monitor_mode'] != 'all-selectors' and args['monitor_mode'] != 'all-events'):
        sys.exit("Exiting - Invalid Monitor Mode: {0}".format(args['monitor_mode']))

    # validate target-list-id
    if args['target_list_id'] is not None or args['monitor_mode'] == 'target-list':
        try:
            int(args['target_list_id'])
        except ValueError:
            sys.exit("Exiting - Invalid Target List ID: {0}".format(args['target_list_id']))
        except TypeError:
            sys.exit("Exiting - Target List ID Required in this Monitor Mode: {0}".format(args['monitor_mode']))

    #validate target process threshold
    if args['target_threshold'] is not None:
        try:
            args['target_threshold'] = int(args['target_threshold'])
        except ValueError:
            sys.exit("Exiting - Invalid Target Threshold: {0}".format(args['target_threshold']))
    else:
        args['target_threshold'] = 15

    #validate alert interval
    if args['alert_interval'] is not None:
        try:
            args['alert_interval'] = int(args['alert_interval'])
        except ValueError:
            sys.exit("Exiting - Invalid Alert Interval: {0}".format(args['alert_interval']))

    #validate channel lock
    if args['channel_lock'] is not None:
        try:
            if not int(args['channel_lock']) in range(1,12):
                sys.exit("Exiting - Invalid Channel Lock: {0}".format(args['channel_lock']))
        except ValueError:
            sys.exit("Exiting - Invalid Channel Lock: {0}".format(args['channel_lock']))

    #validate tor port
    if args['tor_port'] is not None:
        try:
            int(args['tor_port'])
        except ValueError:
            sys.exit("Exiting - Invalid TOR Port: {0}".format(args['tor_port']))


    #validate the interface is up and in monitor mode
    try:
        mode = subprocess.check_output('cat /sys/class/net/{0}/type'.format(args['monitor_interface']), shell=True).decode().strip()
        if mode != '803':
            sys.exit("Exiting - Interface not in Monitor Mode: {0}".format(args['monitor_interface']))
        status = subprocess.check_output('cat /sys/class/net/{0}/operstate'.format(args['monitor_interface']), shell=True).decode().strip().lower()
        if status == 'down':
            sys.exit("Exiting - Interface Down: {0}".format(args['monitor_interface']))
    except Exception as err:
        sys.exit("Exiting - Invalid Monitor Interface: {0}".format(args['monitor_interface']))


    try:
        if args['gps_coordinates'] != 'dynamic':
            coords = [float(x) for x in args['gps_coordinates'].split(',')]

            #check if coordinates are in proper range
            if not(-90.0 <= coords[0] <= 90.0 and -180.0 < coords[1] < 180.0):
                sys.exit("Exiting - Invalid GPS Coordinates: {0}".format(args['gps_coordinates']))
    except:
        sys.exit("Exiting - Invalid GPS Coordinates: {0}".format(args['gps_coordinates']))


    if args['channel_dwell'] is not None:
        try:
            args['channel_dwell'] = float(args['channel_dwell'])
        except ValueError:
            sys.exit("Exiting - Invalid Channel Hold Value: {0}".format(args['channel_dwell']))


    return args

def channel_lock(interface, channel):
    os.system('iwconfig {0} channel {1}'.format(interface, channel))

def channel_hop(interface):
    channel = 1
    dwell_time = .5
    if ARGS['channel_dwell'] is not None:
        dwell_time = ARGS['channel_dwell']
    while True:
        #print(channel)
        os.system('iwconfig {0} channel {1}'.format(interface, channel))
        time.sleep(int(dwell_time))
        if channel == 1:
            channel = 6
        elif channel == 6:
            channel = 11
        else:
            channel = 1

def start_channel_hop(interface):
    thread = threading.Thread(target=channel_hop, args=(interface, ), name="channel_hop")
    thread.daemon = True
    thread.start()

def hopper(iface):
    n = 1
    stop_hopper = False
    while not stop_hopper:
        time.sleep(0.50)
        os.system('iwconfig %s channel %d' % (iface, n))
        print("Current Channel %d" % (n))
        dig = int(random.random() * 14)
        if dig != 0 and dig != n:
            n = dig

if __name__ == "__main__":
    main()
