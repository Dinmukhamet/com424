import sys
from collections import Counter

import scans
from db import db, Intruder


def main():
    filename = sys.argv[1]
    db.connect()
    db.create_tables([Intruder])
    scans_array = (
        scans.XmasScan,
        scans.UDPScan,
        scans.HalfOpenScan,
        scans.NULLScan,
        scans.ICMPEcho,
    )
    for scan in scans_array:
        scan(filename=filename).summary


if __name__ == "__main__":
    main()
