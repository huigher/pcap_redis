# -*- coding: utf-8 -*-
import datetime, calendar,time
import random
import sys
import logging
import json


def timstamp2timestring(timestamp=None):
    if not timestamp:
        timestamp=time.time()
    time_tuple = time.localtime(timestamp)
    date_str = time.strftime("%Y-%m-%d %H:%M:%S.%s", time_tuple)
    return date_str
