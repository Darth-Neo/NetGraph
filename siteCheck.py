#!/usr/bin/env python
#
# __author__ = 'james.morris'
import os
import logging
import logging.handlers

from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import traceroute

DEBUG = logging.DEBUG
INFO = logging.INFO
WARN = logging.WARN
ERROR = logging.ERROR

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

    logger.info("IP : %s" % IP)
    logger.info("%sconf.route : %s" % (os.linesep, conf.route))

    n = 0
    r = None
    u = None

    listSites = list()
    listSites.append("google-public-dns-b.google.com")
    listSites.append("google-public-dns-a.google.com")

    for site in listSites:
        logger.info("%sTraceroute for %s" % (os.linesep, site))
        r, u = traceroute(site, maxttl=20)



