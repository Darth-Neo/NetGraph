#!/usr/bin/env python
from Logger import *
logger = setupLogging(__name__)
logger.setLevel(DEBUG)


if __name__ == u"__main__":

    fileBookmarks = u"data" + os.sep + u"bookmarks.pl"

    bookmarks = loadList(fileBookmarks)

    logList(bookmarks)
