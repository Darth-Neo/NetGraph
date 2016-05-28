#!/usr/bin/env python
#
# __author__ = 'james.morris'
import os

from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import traceroute

from Logger import *
logger = setupLogging(__name__)
logger.setLevel(DEBUG)


if __name__ == u"__main__":
    logger = setupLogging(__name__)
    logger.setLevel(INFO)

    logger.info(u"IP : %s" % IP)
    logger.info(u"%sconf.route : %s" % (os.linesep, conf.route))

    n = 0
    r = None
    u = None

    listSites = list()
    listSites.append("google-public-dns-b.google.com")
    listSites.append("google-public-dns-a.google.com")

    for site in listSites:
        logger.info("%sTraceroute for %s" % (os.linesep, site))
        r, u = traceroute(site, maxttl=20)



