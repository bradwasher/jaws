from scapy.all import *
from datetime import datetime


class Sensor:
    def __init__(self, sensor_id, interface, api, location, batch_id="", batch_description="", target_list=[], mode="all-selectors", cool_down=15):
        self.sensor_id = sensor_id
        self.interface = interface
        self.batch_id = batch_id
        self.batch_description = batch_description
        self.target_list = target_list
        self.mode = mode
        self.cool_down = cool_down
        self.api = api
        self.location = location

        self._running = False

        self.seen_identifiers = {}

        self.template = {}
        self.template["sensor_id"] = self.sensor_id
        self.template["batch_id"] = self.batch_id
        self.template["batch_description"] = self.batch_description

        if mode != "all-selectors" and mode != "target-list":
            raise ValueError("Invalid collection mode specified")

    def run(self):
        self._running = True
        #sniff(iface=self.interface, prn=self.__packet_handler, store=0, count=0, stop_filter=self.__stop_filter)
        sniff(iface=self.interface, prn=self._packet_handler, store=0, count=0)

    def stop(self):
        self._running = False

    def _stop_filter(self, pkt):
        return self._running

    def _packet_handler(self, pkt):
        """
        if the collection mode is 'target-list' then identify if either the src_mac or dst_mac
        are in the target deck.  If so, then also check to see if the target is within the
        threshold since a packet was last processed from it.  Since target-list mode is generally
        used just to identify targets within range and simple metrics, most packets are dropped
        so that the web server and database aren't inundated with posts. The exception is that
        EAPOL records are always captured
        :param pkt:
        :return:
        """
        timestamp = datetime.utcnow()
        record = {}
        #print(f"PH - {str(timestamp)}")


        if pkt.haslayer(EAPOL):
            print(f"EAPOL - {str(timestamp)}")
            record = self._create_record(pkt, timestamp)
            record['record_type'] = 'eapol'
            eapol = []
            for x in pkt.getlayer(Raw):
                eapol.append(x.load.hex())
            if len(eapol) > 0:
                record['eapol'] = ''.join(eapol)

        elif self.mode == 'target-list':
            target = self._target_found(pkt)
            if target and _allow_collect(target, timestamp):
                record = self._create_record(pkt, timestamp)
                record['record_type'] = 'target-hit'
                record['target_hit'] = {}
                record['target_hit']['target'] = target

        elif self.mode == 'all-selectors':
            record = self._create_record(pkt, timestamp)
            record['record_type'] = 'selector-collect'

            collect = False
            for identifier in record['macs']:
                if self._allow_collect(identifier, timestamp):
                    collect = True
            if not collect:
                record = None

        if record:
            self.api.queue_record(record)

    def _create_record(self, pkt, timestamp):

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
            type_desc = 'Management'
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

        record = self.template

        #record['sensor_timestamp'] = f'{timestamp:%Y-%m-%d %H:%M:%S%z}'
        record['sensor_timestamp'] = str(timestamp)
        record['sensor_location'] = self.location.get_location()
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

        return record

    def _target_found(self, pkt):
        header = object

        if Dot11 in pkt:
            header = pkt.getlayer(Dot11)
        elif Dot11FCS in pkt:
            header = pkt.getlayer(Dot11FCS)

        if hasattr(header, 'addr1') and header.addr1 is not None:
            addr1 = header.addr1.lower().replace(':', '')
            if addr1 in TARGETS:
                return addr1

        if hasattr(header, 'addr2') and header.addr2 is not None:
            addr2 = header.addr2.lower().replace(':', '')
            if addr2 in TARGETS:
                return addr2

        return False

    def _allow_collect(self, identifier, timestamp):
        collect_identifier = False

        if identifier not in self.seen_identifiers:
            collect_identifier = True
            self.seen_identifiers[identifier] = timestamp
        else:
            diff = timestamp - self.seen_identifiers[identifier]
            #print('diff: {0}  now {1}  --  past {2}'.format(diff.seconds, timestamp, THRESHOLD[target]))
            if diff.seconds > self.cool_down:
                collect_identifier = True
                self.seen_identifiers[identifier] = timestamp

        return collect_identifier
