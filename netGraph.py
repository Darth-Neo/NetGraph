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


def netGraph():
    index = 0

    if len(sys.argv) > 1:
        pgm = sys.argv[0]
        csvFile = sys.argv[1]
        logger.info(u"%s - %s" % (pgm, csvFile))
        index = 0
    else:
        csvFile = u".%stop500.csv" % os.sep
        index = 1

    NUM_SITES = 500

    logger.info(u"Start...")
    logger.debug(u"IP : %s" % IP)
    logger.info(u"%sroute : %s" % (os.linesep, conf.route))

    n = 0
    r = u = None

    #
    # This MUST be a string. not unicode!
    #
    site = "www.disney.com"
    logger.info(u"Traceroute for %s" % site)

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
                logger.info(u"%s%d - %s ->%s" % (os.linesep, n, site[-3:], site))
                if True or site[-3:] in (u"com", u"gov", u"org"):
                    try:
                        r, u = traceroute(site, maxttl=20)
                        rt = rt + r
                        n += 1
                    except Exception, msg:
                        logger.info(u"%s" % msg)

    logger.info(u"Building Graph...")
    # rt.graph(resolve=True, target="> ./g.svg")
    rt.graph(target=u"> ./g.svg")

    logger.info(u"Complete")

if __name__ == u"__main__":
    netGraph()
