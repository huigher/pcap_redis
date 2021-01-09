import pyshark
import os
import platform
import threading
import time
from scapy.all import rdpcap
import Utils
import dpkt
import socket
import collections
import nest_asyncio

nest_asyncio.apply()


def tmp1():
    caps = pyshark.FileCapture('include1streams.pcap')
    for i in range(9999):
        try:
            print(caps[i])
        except KeyError as ke:
            break

    print(len(caps))
    a = caps[0]
    b = caps[1]
    c = caps[2]
    d = caps[3]
    time = a.frame_info.number
    print(c.highest_layer)
    a_str = f'time is {time}'
    print(a_str)


def tmp2():
    a = None
    b = None
    c = True
    d = 'infinity' if not a else 4 - 2
    print(d)


def tmp3():
    for i in range(1024, 1100):
        print(i)


def tmp4():
    for path, dir_list, file_list in os.walk(r'tmp/'):
        for file_name in file_list:
            print(os.path.join(path, file_name))


def tmp5():
    caps = rdpcap('include1streams.pcap')
    for packet in caps:
        if 'TCP' in packet:
            ip = packet['IP']
            tcp = packet['TCP']
            if packet['TCP'].payload.name == 'Raw':
                print(str(packet['TCP'].payload.load))
            print(Utils.timstamp2timestring(float(packet.time) * 1000))
            # print(packet.show())


def tmp6():
    print(time.time())
    f = open('include1streams.pcap', mode='rb')
    caps = dpkt.pcap.Reader(f)
    all_pcap_data = collections.OrderedDict()  # 有序字典
    for (timestamp, buffer) in caps:
        try:
            packet = {'eth': dpkt.ethernet.Ethernet(buffer), 'ip': None, 'tcp': None, 'data': None}
            if isinstance(packet['eth'].data, dpkt.ip.IP):  # 解包，网络层，判断网络层是否存在，
                packet['ip'] = packet['eth'].data
                if isinstance(packet['ip'].data, dpkt.tcp.TCP):  # 解包，判断传输层协议是否是TCP，即当你只需要TCP时，可用来过滤
                    packet['tcp'] = packet['ip'].data
                    if not len(packet['tcp'].data) == 0:  # 如果应用层负载长度为0，即该包为单纯的tcp包，没有负载，则丢弃
                        packet['data'] = packet['tcp'].data
            all_pcap_data[timestamp] = packet  # 将时间戳与应用层负载按字典形式有序放入字典中，方便后续分析.
            # print('src:'+socket.inet_ntoa(packet['ip']['src']))
        except Exception as err:
            print("[error] %s" % err)
    # print(all_pcap_data)
    print(time.time())


def tmp7():
    print(time.time())
    caps = pyshark.FileCapture('redis.pcap', only_summaries=True)
    print(time.time())
    for cap in caps:
        print('.', end='')
    print(len(caps))
    print(time.time())


def UsePlatform():
    a = platform.system()
    print(a)


class ana_worker(threading.Thread):
    def __init__(self, cap_filename, tcp_stream_index):
        super().__init__()
        self.tcp_stream_index = tcp_stream_index
        self.caps = pyshark.FileCapture(cap_filename, display_filter='tcp.stream==' + str(tcp_stream_index))

    def run(self):
        print('Thread ' + str(self.tcp_stream_index) + ' started.')
        for cap in self.caps:
            print('Thread ' + str(self.tcp_stream_index) + ' got a packet.')
        print('Finished.stream_index==' + str(self.tcp_stream_index))
        self.caps.close_async()


def tmp8():
    thread_dict = dict()
    for i in range(10):
        thread_dict[i] = ana_worker('redis.pcap', i)
        thread_dict[i].start()


a=platform.system()
print(a)