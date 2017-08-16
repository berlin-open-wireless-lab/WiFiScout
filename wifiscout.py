#!/usr/bin/env python3

import argparse
import datetime
import json
import os
import sys
import uuid

import pyshark
import netifaces

import fingerbank
from manuf import get_oui_vendor_name

OUTPUT_PATH = 'output/'
DB_JSON_FILE_NAME = 'device.json'

# Value of type field for each request
PROBE_REQUEST = '4'
ASSOCIATION_REQUEST = '0'
DHCP_REQUEST = '1'

# Filter to parse only the packets we are interested in:
#   - Probe requests
#   - Association requests
#   - DHCP requests
FILTER = "( wlan.fc.type == 0 && ( wlan.fc.subtype == 0 || wlan.fc.subtype == 4 ))"
FILTER += " || bootp.type == 1"  # DHCP requests
FILTER += " || http"  # HTTP packets

# SSID
ssid = ""

# Seen BSSIDs
bssids = []

# Clients
clients_mac = []
clients = {}


def parse_mlme_request(packet):
    res = ""
    mgt = packet.wlan_mgt

    first = True
    vendor_done = False
    for f in mgt.tag_number.all_fields:
        if f.show == "221":
            if not vendor_done:
                for i, v in enumerate(mgt.tag_oui.all_fields):
                    if not first:
                        res += ","
                    first = False
                    t = mgt.tag_vendor_oui_type.all_fields[i]
                    res += '221('
                    res += v.raw_value
                    res += ','
                    res += t.show
                    res += ')'
                vendor_done = True
        else:
            if not first:
                res += ","
            first = False
            res += f.show

    if hasattr(mgt, 'ht_capabilities'):
        res += ",htcap:"
        res += mgt.ht_capabilities[-4:]
    if hasattr(mgt, 'ht_ampduparam'):
        res += ",httag:"
        res += mgt.ht_ampduparam[-2:]
    if hasattr(mgt, 'ht_mcsset_rxbitmask_0to7'):
        res += ",htmcs:"
        res += mgt.ht_mcsset_rxbitmask_0to7[2:]
    if hasattr(mgt, 'extcap'):
        res += ",extcap:"
        mask = ""
        for b in mgt.extcap.all_fields:
            mask += b.show[-2:]
        res += mask
    if hasattr(mgt, 'wps_model_name'):
        res += ",wps:"
        res += mgt.wps_model_name

    return res


def handler_probe_request(packet):
    probe = "probe:"

    probe += parse_mlme_request(packet)

    clients[packet.wlan.sa]["wifi_signature"] += probe
    print(packet.number, " Probe request: {0} -> {1}".format(packet.wlan.sa, packet.wlan.da))


def handler_assoc_request(packet):
    assoc = "|assoc:"

    assoc += parse_mlme_request(packet)

    clients[packet.wlan.sa]["wifi_signature"] += assoc
    print(packet.number, " Association request: {0} -> {1}".format(packet.wlan.sa, packet.wlan.da))


def handler_dhpc_request(packet):
    dhcp_fingerprint = ""
    first = True
    for f in packet.bootp.option_request_list_item.all_fields:
        if not first:
            dhcp_fingerprint += ","
        first = False
        dhcp_fingerprint += f.show
    clients[packet.wlan.sa]["dhcp_fingerprint"] = dhcp_fingerprint
    clients[packet.wlan.sa]["dhcp_vendor"] = packet.bootp.option_vendor_class_id
    print(packet.number, " DHCP request: {0} -> {1}".format(packet.wlan.sa, packet.wlan.da))


def handler_http_ua(packet):
    clients[packet.wlan.sa]["user_agent"] = packet.http.user_agent
    print(packet.number, " User-Agent: {0} -> {1}".format(packet.wlan.sa, packet.wlan.da))


def handler_packet(packet, ssid):

    if hasattr(packet, 'wlan'):
        da = packet.wlan.da
        sa = packet.wlan.sa
        fc_subtype = packet.wlan.fc_type_subtype

        if hasattr(packet, 'wlan_mgt'):
            if fc_subtype == PROBE_REQUEST:
                if sa not in clients_mac:
                    clients[sa] = {
                        "oui": sa[0:8],
                        "wifi_signature": "wifi4|",
                        "dhcp_vendor": "",
                        "dhcp_fingerprint": "",
                        "user_agent": ""
                    }
                    clients_mac.append(sa)
                    handler_probe_request(packet)

            if packet.wlan_mgt.ssid == ssid:
                if da not in bssids:
                    bssids.append(da)
                    print("New BSSID: ", da)

                if fc_subtype == ASSOCIATION_REQUEST:
                    handler_assoc_request(packet)

        if sa in clients_mac:
            if hasattr(packet, 'bootp'):
                if clients[sa]["dhcp_fingerprint"] is "":
                    if packet.bootp.type == DHCP_REQUEST:
                        handler_dhpc_request(packet)
            if hasattr(packet, 'http'):
                if clients[sa]["user_agent"] is "":
                    handler_http_ua(packet)


def handler_file(args):
    if not os.path.isfile(args.file):
        print("ERROR: the specified file does not exist.")
        sys.exit(-1)

    filter = FILTER
    cap = pyshark.FileCapture(args.file, display_filter=filter)

    for packet in cap:
        handler_packet(packet, args.ssid)


def handler_int(args):
    if args.interface not in netifaces.interfaces():
        print("ERROR: the specified interface does not exist.")
        sys.exit(-1)

    filter = FILTER
    cap = pyshark.LiveCapture(args.interface, display_filter=filter)

    return cap


def main():
    parser = argparse.ArgumentParser()
    exc_input = parser.add_mutually_exclusive_group()
    querying_method = parser.add_argument_group("querying method")
    exc_query = querying_method.add_mutually_exclusive_group()

    parser.add_argument('ssid', type=str,
                        help='the SSID of the network to monitor')
    exc_input.add_argument('-f', '--file', type=str,
                                 help='the pcap file to analyze')
    exc_input.add_argument('-i', '--interface', type=str,
                                 help='the wifi interface to capture from')
    exc_query.add_argument('--api', help='query the Fingerbank API',
                           action="store_true")
    exc_query.add_argument('--db', help='query the Fingerbank SQLite db',
                           action="store_true")

    args = parser.parse_args()

    if args.api:
        API_KEY = os.environ.get('FINGERBANK_API_KEY')

        if API_KEY is None:
            print("ERROR: FINGERBANK_API_KEY env variable is not set.")
            sys.exit(-1)
    elif args.db:
        DB_PATH = os.getenv('FINGERBANK_SQLITE_PATH', 'packaged.sqlite3')

        if not os.path.isfile(DB_PATH):
            print("ERROR: The database file (%s) does not exist." % (DB_PATH))
            sys.exit(-1)
    else:
        print("You must either use --api or --db.")
        sys.exit(-1)

    if args.file:
        print("Parsing tracefile...")
        handler_file(args)
    elif args.interface:
        handler_int(args)

    valid_clients = {i: clients[i] for i in clients if clients[i]["dhcp_vendor"] != ""}

    print()

    if args.api:
        print("Querying the Fingerbank API...")

        for client in valid_clients:
            res = fingerbank.get_device_api(clients[client], API_KEY)
            if res:
                valid_clients[client]["name"] = res["name"]
    elif args.db:
        print("Querying the Fingerbank database...")

        import sqlite3

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        for client in valid_clients:
            res = fingerbank.get_device_db(clients[client], c)
            if res:
                valid_clients[client]["name"] = res["name"]

        conn.close()

    device = {}

    for c in valid_clients:
        device["uuid"] = str(uuid.uuid4())
        device["name"] = valid_clients[c]["name"]
        device["wifi_signature"] = valid_clients[c]["wifi_signature"]
        device["mac_vendor"] = get_oui_vendor_name(valid_clients[c]["oui"], "manuf")
        device["created_at"] = str(datetime.datetime.now())
        device["modified_at"] = device["created_at"]
        device["image_url"] = ""

        device_path = OUTPUT_PATH + device["uuid"] + '/'

        if not os.path.exists(device_path):
            os.makedirs(device_path)

        with open(device_path + DB_JSON_FILE_NAME, 'w') as f:
            f.write(json.dumps(device, indent=4))

        print(json.dumps(device, indent=2, separators=(',', ': ')))


if __name__ == "__main__":
    main()
