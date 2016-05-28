#!/usr/bin/env python
import os
import sys
import csv
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import traceroute

from Logger import *
logger = setupLogging(__name__)
logger.setLevel(DEBUG)

"""
from netGraphDomain import *
netGraph()
"""


def netGraph():
    index = 0

    domainFile = u"data/disney_20160521.csv"
    index = 1
    n = 0
    NUM_SITES = 200

    logger.info(u"Start...")
    logger.debug(u"IP : %s" % IP)
    logger.info(u"%sroute : %s" % (os.linesep, conf.route))

    #
    # This MUST be a string. not unicode!
    #
    site = "www.disney.com"
    logger.info(u"Traceroute for %s" % site)
    rt, ut = traceroute(site, maxttl=20)

    # rt.show()

    with open(domainFile, "rb") as dfile:

        # Skip first line
        urls = dfile.readlines()

    for url in urls:
        n += 1
        url = url.strip()
        logger.info(u"%s%d - %s" % (os.linesep, n, url))

        try:
            r, u = traceroute(url, maxttl=20)
            rt = rt + r
            n += 1

        except Exception, msg:
            logger.info(u"%s" % msg)

    logger.info(u"Building Graph...")
    # rt.graph(resolve=True, target="> ./g.svg")
    rt.graph(target=u"> ./run/g.svg")

    logger.info(u"Complete")

if __name__ == u"__main__":
    netGraph()
