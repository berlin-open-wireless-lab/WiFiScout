# WiFiScout

**Note:** currently only works with a tracefile, live capture will be implemented *soon*™.

## Setup

You need to have `tshark` installed. It generally comes with Wireshark.

### SQLite database

If you want to use the Fingerbank SQLite database, you will need to download it
and set the `$FINGERBANK_SQLITE_PATH` env variable accordingly.

e.g: `export FINGERBANK_SQLITE_PATH="packaged.sqlite3"`

### API

If you want to use the Fingerbank API, you will need to register for an API key
and set the `$FINGERBANK_API_KEY` env variable accordingly.

e.g: `export FINGERBANK_API_KEY="ABCDEF123456789"`

### OUI database

You need a wireshark OUI database file for OUI lookups. The last version is available at https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf;hb=HEAD

Save it as `manuf`.

### Python dependencies

```
pip install -r requirements.txt
```

A `Pipfile` is included if you are familiar with [`pipenv`](https://github.com/kennethreitz/pipenv).

## Run

```
usage: collector.py [-h] [-f FILE | -i INTERFACE] [--api | --db] ssid

positional arguments:
  ssid                  the SSID of the network to monitor

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  the pcap file to analyze
  -i INTERFACE, --interface INTERFACE
                        the wifi interface to capture from

querying method:
  --api                 query the Fingerbank API
  --db                  query the Fingerbank SQLite db
```

Found devices information will be stored in the `OUTPUT_PATH` (see `collector.py`) folder.
