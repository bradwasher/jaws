# global modules
import argparse
import time
import subprocess
import sys

# local modules
from location import Location
from webapi import WebAPI
from monitor_interface import MonitorInterface
from sensor import Sensor


def main():

    # get and validate command-line arguments
    args = get_args()

    print('''   
       ,(   ,(   ,(   ,(   ,(   ,(   ,(   ,(   ,(   ,(   ,(
     .'  `-'  `-'  `-'  `-'  `-'  `-'  `-'  `-'  `_'  `_'  `.
         
                                     _________         .    . 
                                    (..       \_    ,  |\  /|
       ___                           \       O  \  /|  \ \/ /                 
      |_  |                           \______    \/ |   \  /       
        | | __ ___      _____            vvvv\    \ |   /  |
        | |/ _` \ \ /\ / / __|           \^^^^  ==   \_/   | 
    /\__/ / (_| |\ V  V /\__ \\            `\_   ===    \.  |
    \____/ \__,_| \_/\_/ |___/            / /\_   \ /      | 
                                          |/   \_  \|      /
                                                 \________/
    
    JUST ANOTHER WiFi SENSOR                              v1.0
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        ''')

    try:
        loc = Location(args["gps_mode"])
        loc.run()

        iface = MonitorInterface(args["monitor_interface"], args["channel_mode"], args["channel_lock"], args["channel_dwell"])
        iface.run()

        api = WebAPI(args["collection_point_url"], jwt=args["json_web_token"])
        chk = api.check_in({"sensor_id":args["sensor_id"], "mode":args["monitor_mode"]})
        api.start()

        sense = Sensor(args["sensor_id"], args["monitor_interface"], api, loc)
        sense.run()

    except (KeyboardInterrupt, SystemExit):  # when you press ctrl+c
        sense.stop()

        api.stop()
        api.join()

        loc.stop_polling()
        iface.stop_hopping()


def get_args():
    """
    Get and validate command line arguments and return dictionary of those key/values
    :return:
    """
    ap = argparse.ArgumentParser()
    ap.add_argument("-s", "--sensor-id", required=True, help="ID of the sensor that is passed to the collection point with each record")
    ap.add_argument("-c", "--collection-point-url", required=True, help="URI of the collection point where records are posted via http")
    ap.add_argument("-m", "--monitor-mode", required=True, help="monitor mode of sensor; can be 'target-list' or 'all-selectors'")
    ap.add_argument("-t", "--target-list-id", required=False, help="integer identifier of MAC target list to retrieve when sensor first checks in")
    ap.add_argument("-o", "--cool-down", required=False, help="time in seconds between target hit alerts in seconds; defaults to 15")
    ap.add_argument("-a", "--alert-interval", required=False, help="interval in seconds between when records are posted to collection point; defaults to 15")
    ap.add_argument("-i", "--monitor-interface", required=True, help="network interface the sensor is using to collect data" )
    ap.add_argument("-g", "--gps-mode", required=True, help="if value is 'dynamic' then attempt to get location from gps device; otherwise input static coordinates of sensor (eg '1.234,5.678')")
    ap.add_argument("-b", "--batch-id", required=False, help="an identifier for this batch of collection")
    ap.add_argument("-d", "--batch-description", required=False, help="a description for this batch of collection")
    ap.add_argument("-j", "--json-web-token", required=True, help="authorization token used to allow access to web api")
    ap.add_argument("-l", "--channel-lock", required=False, help="channel to lock on to for collection; default or 0 is to hop between 1, 6, and 11 every 1000 ms")
    ap.add_argument("-w", "--channel-dwell", required=False, help="value in seconds to stay on a channel if in channel hopping mode; default is .5")
    ap.add_argument("-z", "--channel-mode", required=False, help="hop or lock")

    args = vars(ap.parse_args())
    #print(args)

    # validate monitor mode
    if args['monitor_mode'] is not None and (args['monitor_mode'] != 'target-list' and args['monitor_mode'] != 'all-selectors' and args['monitor_mode'] != 'all-events'):
        sys.exit(f"Exiting - Invalid Monitor Mode: {args['monitor_mode']}")

    # validate target-list-id
    if args['target_list_id'] is not None or args['monitor_mode'] == 'target-list':
        try:
            int(args['target_list_id'])
        except ValueError:
            sys.exit(f"Exiting - Invalid Target List ID: {args['target_list_id']}")
        except TypeError:
            sys.exit(f"Exiting - Target List ID Required in this Monitor Mode: {args['monitor_mode']}")

    # validate target process threshold
    if args['cool_down'] is not None:
        try:
            args['cool_down'] = int(args['cool_down'])
        except ValueError:
            sys.exit(f"Exiting - Invalid Cool Down: {args['cool_down']}")
    else:
        args['cool_down'] = 15

    #validate alert interval
    if args['alert_interval'] is not None:
        try:
            args['alert_interval'] = int(args['alert_interval'])
        except ValueError:
            sys.exit(f"Exiting - Invalid Alert Interval: {args['alert_interval']}")
    else:
        args['alert_interval'] = 15

    #validate channel lock
    if args['channel_lock'] is not None:
        try:
            if not int(args['channel_lock']) in range(1,12):
                sys.exit(f"Exiting - Invalid Channel Lock: {args['channel_lock']}")
        except ValueError:
            sys.exit(f"Exiting - Invalid Channel Lock: {args['channel_lock']}")
    else:
        args["channel_lock"] = 0


    # validate the interface is up and in monitor mode
    try:
        mode = subprocess.check_output(f"cat /sys/class/net/{args['monitor_interface']}/type", shell=True).decode().strip()
        if mode != '803':
            sys.exit(f"Exiting - Interface not in Monitor Mode: {args['monitor_interface']}")
        status = subprocess.check_output(f"cat /sys/class/net/{args['monitor_interface']}/operstate", shell=True).decode().strip().lower()
        if status == 'down':
            sys.exit(f"Exiting - Interface Down: {args['monitor_interface']}")
    except Exception as err:
        sys.exit(f"Exiting - Invalid Monitor Interface: {args['monitor_interface']}")


    try:
        if args['gps_mode'] != 'dynamic':
            coords = [float(x) for x in args['gps_mode'].split(',')]

            # check if coordinates are in proper range
            if not(-90.0 <= coords[0] <= 90.0 and -180.0 < coords[1] < 180.0):
                sys.exit(f"Exiting - Invalid GPS Coordinates: {args['gps_mode']}")
    except:
        sys.exit(f"Exiting - Invalid GPS Coordinates: {args['gps_mode']}")


    if args['channel_dwell'] is not None:
        try:
            args['channel_dwell'] = float(args['channel_dwell'])
        except ValueError:
            sys.exit(f"Exiting - Invalid Channel Hold Value: {args['channel_dwell']}")
    else:
        args["channel_dwell"] = 0


    return args


def dprint(string):
    __builtins__.print("%f -- %s" % (time.time(), string))


if __name__ == "__main__":
    main()

