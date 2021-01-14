# -*- coding: utf-8 -*-
import time


def timstamp2timestring(timestamp=None):
    if not timestamp:
        timestamp=time.time()
    time_tuple = time.localtime(timestamp)
    date_str = time.strftime("%Y-%m-%d %H:%M:%S", time_tuple)
    return date_str
