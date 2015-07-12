#!/usr/bin/env python
#
# __author__ = 'james.morris'
import os
import sys
import csv
import logging
import logging.handlers

DEBUG = logging.DEBUG
INFO = logging.INFO
WARN = logging.WARN
ERROR = logging.ERROR

from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import traceroute

def setupLogging(name):
    #
    # Logging setup
    #
    logger = logging.getLogger(name)
    logFile = './log.txt'

    # Note: Levels - DEBUG INFO WARN ERROR CRITICAL
    logger.setLevel(logging.INFO)

    logFormatter = logging.Formatter("%(asctime)s [%(levelname)-5.5s] [%(filename)s:%(lineno)s ] %(message)s")

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    logger.addHandler(consoleHandler)

    fileHandler = logging.handlers.RotatingFileHandler(logFile, maxBytes=10485760, backupCount=5)
    fileHandler.setFormatter(logFormatter)
    logger.addHandler(fileHandler)

    return logger


if __name__ == "__main__":
    logger = setupLogging(__name__)
    logger.setLevel(INFO)
    index = 0

    if len(sys.argv) > 1:
        pgm = sys.argv[0]
        csvFile = sys.argv[1]
        logger.info("%s - %s" % (pgm, csvFile))
        index = 0
    else:
        csvFile = ".%stop500.csv" % os.sep
        index = 1

    NUM_SITES = 200

    logger.info("Start...")
    logger.debug("IP : %s" % IP)
    logger.info("route : %s" % conf.route)

    n = 0
    r = u = None

    site = "www.disney.com"
    logger.info("Traceroute for %s" % site)

    rt, ut = traceroute(site, maxttl=20)

    # rt.show()

    with open(csvFile, 'rb') as csvfile:
        # Skip first line
        csvfile.readline()
        siteRow = csv.reader(csvfile, delimiter=',', quotechar='"')

        for row in siteRow:

            if index == 0:
                site = row[index]
            else:
                site = row[index][:-1]

            if n > NUM_SITES:
                break
            else:
                logger.info("%s%d - %s ->%s" % (os.linesep, n, site[-3:], site))
                if True or site[-3:] in ("com", "gov", "org"):
                    try:
                        r, u = traceroute(site, maxttl=20)
                        rt = rt + r
                        n += 1
                    except Exception, msg:
                        logger.info("%s" % msg)

    logger.info("Building Graph...")
    # rt.graph(resolve=True, target="> ./g.svg")
    rt.graph(target="> ./g.svg")

    logger.info("Complete")

