import pyshark
import os

def tmp1():
    caps=pyshark.FileCapture('redis.pcap',use_json=True,only_summaries=True)
    a=caps[0]
    b=caps[1]
    c=caps[2]
    d=caps[3]
    time=a.frame_info.number
    print(c.highest_layer)
    a_str=f'time is {time}'
    print(a_str)

def tmp2():
    a=None
    b=None
    c=True
    d='infinity' if not a else 4-2
    print(d)

def tmp3():
    for i in range(1024,1100):
        print(i)

def tmp4():
    for path, dir_list, file_list in os.walk(r'tmp/'):
        for file_name in file_list:
            print(os.path.join(path, file_name))

tmp4()
