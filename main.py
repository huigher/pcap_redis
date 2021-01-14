# coding=utf-8
import argparse
import dpkt
import subprocess
import io
import tempfile
import socket
import collections
import platform
import Utils
import uuid
import os


class redis_analyzer:
    def __init__(self, capture_filename, timeout_threshold, output_filename, parser='dpkt', debug=False):
        self.capture_filename = capture_filename
        self.timeout_threshold = timeout_threshold
        self.output_filename = output_filename
        self.output_writer = open(output_filename, 'a')
        self.parse = parser
        self.debug = debug

        # 设定一些常数
        self.TCP_STREAM_COUNTS = 99999
        self.REDIS_PORT = 6379
        self.L7_PROTOCOL_NAME = 'redis'

        # 存放一些公共临时参数
        self.request_cap = None
        self.response_cap = None
        self.request_cap_index = None
        self.response_cap_index = None
        self.split_filename = None
        # self.tcp_stream_number = None

        # 设定一个临时目录
        self.tmp_folder_name = str(uuid.uuid1())
        self.tmp_full_folder_path = tempfile.gettempdir() +os.sep+ self.tmp_folder_name + os.sep

        # 根据操作系统配置一些操作系统相关的变量
        if platform.system() == 'Darwin':
            self.pcapplusplus_name = r'PcapSplitter_macos_catalina'
        elif platform.system() == 'Linux':
            self.pcapplusplus_name = r'PcapSplitter_centos_7_gcc'
        elif platform.system()=='Windows':
            self.pcapplusplus_name = r'PcapSplitter_windows_mingw.exe'

        self.my_real_path=os.path.split(os.path.realpath(__file__))[0]

    def initial(self):
        self.output_writer.write(('=' * 50) + '\n')
        self.split_capture_file()

    def split_capture_file(self):
        # 先判断一下Pcapplusplus是否能正常工作
        if not self.pcapplusplus_works:
            if platform=='Windows':
                print()
        folder = os.path.exists(self.tmp_full_folder_path)
        if not folder:  # 判断是否存在文件夹如果不存在则创建为文件夹
            os.makedirs(self.tmp_full_folder_path)

        self.write_log_info('Start to split capture file,temporarily folder is ' + self.tmp_full_folder_path)
        f = os.popen(self.my_real_path+os.sep+r'bin'+os.sep+self.pcapplusplus_name+' -m connection -f ' + self.capture_filename + ' -o ' + self.tmp_full_folder_path)
        self.write_log_info('Splitting Finished.Result: \n' + f.read())

    @staticmethod
    def pcapplusplus_works():
        cmd = "PcapSplitter -h"

        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=-1)
        proc.wait()
        stream_stdout = io.TextIOWrapper(proc.stdout, encoding='utf-8')
        stream_stderr = io.TextIOWrapper(proc.stderr, encoding='utf-8')

        str_stdout = str(stream_stdout.read())

        if len(str_stdout) > 10:
            return True
        else:
            return False

    def write_log(self, text, level):
        self.output_writer.write(Utils.timstamp2timestring() + ' - ' + level + ': ' + text + '\n')
        self.output_writer.flush()

    def write_log_info(self, text):
        self.write_log(text, level='INFO')

    def write_log_warning(self, text):
        self.write_log(text, level='WARNING')

    def write_log_debug(self, text):
        if self.debug:
            self.write_log(text, level='DEBUG')

    def go(self):
        self.go_with_dpkt()
        self.write_log_info('Finished.')

    def go_with_dpkt(self):
        self.write_log_info('Start to analyse,Filename is ' + self.capture_filename)
        self.output_writer.flush()
        # 逐个文件分析
        for path, dir_list, file_list in os.walk(self.tmp_full_folder_path):
            for file_name in file_list:
                self.write_log_debug('About to open capture file:' + str(file_name))
                # 设定一些外层的flags
                # 希望找请求报文
                wanna_request = True
                # 已经找到请求报文
                found_request = False
                # 希望找响应报文
                wanna_response = None
                # 进入每一条TCP流
                f = open(self.tmp_full_folder_path + file_name, mode='rb')
                caps = dpkt.pcap.Reader(f)
                ordered_packets = collections.OrderedDict()  # 有序字典
                # 开始轮询抓包文件
                for (timestamp, buffer) in caps:
                    try:
                        packet = {'timestamp': timestamp, 'eth': dpkt.ethernet.Ethernet(buffer), 'ip': None,
                                  'tcp': None, 'data': None}
                        if isinstance(packet['eth'].data, dpkt.ip.IP):  # 解包，网络层，判断网络层是否存在，
                            packet['ip'] = packet['eth'].data
                            if isinstance(packet['ip'].data, dpkt.tcp.TCP):  # 解包，判断传输层协议是否是TCP，即当你只需要TCP时，可用来过滤
                                packet['tcp'] = packet['ip'].data
                                if not len(packet['tcp'].data) == 0:  # 如果应用层负载长度为0，即该包为单纯的tcp包，没有负载，则丢弃
                                    packet['data'] = packet['tcp'].data
                        ordered_packets[timestamp] = packet  # 将时间戳与应用层负载按字典形式有序放入字典中，方便后续分析.
                    except Exception as err:
                        print("[error] %s" % err)
                f.close()
                # 开始分析抓包结果
                cap_index = 1
                for key in ordered_packets:
                    self.write_log_debug(
                        '打开了一个具体的packet，文件名为' + str(file_name) + ',这个packet在流中的序列号为' + str(cap_index))
                    # 设定一些flags
                    is_request = None
                    is_response = None
                    # 给每一个flags置位
                    if int(ordered_packets[key]['tcp']['dport']) == self.REDIS_PORT \
                            and ordered_packets[key]['data'] \
                            and len(ordered_packets[key]['data']) > 0:
                        is_request = True
                        found_request = True
                    else:
                        is_request = False
                    if int(ordered_packets[key]['tcp']['sport']) == self.REDIS_PORT and ordered_packets[key][
                        'data'] and len(ordered_packets[key]['data']) > 0:
                        is_response = True
                    else:
                        is_response = False

                    if is_request:
                        self.write_log_debug('是一个请求包')
                        if wanna_request:
                            self.request_cap = ordered_packets[key]
                            self.request_cap_index = cap_index
                            found_request = True
                            wanna_response = True
                            wanna_request = False
                            cap_index += 1
                            continue
                        else:
                            # 这种场景下一般是客户端提交了一个很大的请求命令，被拆分成了连续的一串请求数据包
                            # 目前的处理逻辑是不断地舍弃前一个请求数据包，将当前的数据包信息作为最新的请求包来储存
                            self.write_log_debug(
                                '存在连续的请求包！Filename:' + self.tmp_full_folder_path + file_name + '.Cap_index:' + str(
                                    cap_index))
                            self.request_cap = ordered_packets[key]
                            self.request_cap_index = cap_index
                            cap_index += 1
                            continue
                    if is_response:
                        self.write_log_debug('是一个响应包')
                        if wanna_response:
                            # 进入最关键的比对逻辑
                            self.response_cap = ordered_packets[key]
                            self.response_cap_index = cap_index
                            self.split_filename = self.tmp_full_folder_path + file_name
                            self.compare_request_and_response()
                            # 清除一下临时的flags
                            wanna_request = True
                            found_request = False
                            wanna_response = False
                            cap_index += 1
                            continue
                        else:
                            # 可能是每一条流的最开始的响应，或者是孤立的响应报文，忽略
                            self.write_log_debug(
                                '发现一条流的第一个包就是响应包。Filename:' + self.tmp_full_folder_path + file_name + '.Cap_index:' + str(
                                    cap_index))
                            cap_index += 1
                            continue
                        # 不是任何感兴趣的包
                    self.write_log_debug('不是感兴趣的包，跳过')
                    cap_index += 1

                self.write_log_debug('抓包文件' + str(file_name) + '已经遍历完毕。')
                # 包里所有的报文都已经遍历完毕，需要处理一下特殊的情况
                if found_request and wanna_response:
                    # 找到了request，但是没有找到任何response

                    self.write_log_debug('找到了一个没有响应的请求包！')
                    self.split_filename = self.tmp_full_folder_path + file_name
                    self.compare_request_and_response()

    def compare_request_and_response(self):
        request_cap_timestamp_mill = 0.00
        response_cap_timestamp_mill = 0.00
        # 先判断一下是否符合记录异常的标准
        is_target_scene = False
        if not self.response_cap:
            # 没有响应报文
            is_target_scene = True
        else:
            # 有响应报文
            if self.parse == 'pyshark':
                request_cap_timestamp_mill = float(self.request_cap.frame_info.time_epoch) * 1000
                response_cap_timestamp_mill = float(self.response_cap.frame_info.time_epoch) * 1000
            elif self.parse == 'scapy':
                request_cap_timestamp_mill = float(self.request_cap.time) * 1000
                response_cap_timestamp_mill = float(self.response_cap.time) * 1000
            elif self.parse == 'dpkt':
                request_cap_timestamp_mill = float(self.request_cap['timestamp']) * 1000
                response_cap_timestamp_mill = float(self.response_cap['timestamp']) * 1000
            else:
                raise Exception()
            if response_cap_timestamp_mill - request_cap_timestamp_mill > self.timeout_threshold:
                # 报文的差值超出了设定的阈值
                is_target_scene = True
        if is_target_scene:
            delta_time = 'undefined'
            header_string = 'undefined'
            response_packet_number = 'undefined'
            if not self.response_cap:
                delta_time = 'infinity'.upper()
                header_string = 'Find a request without response!'
                response_packet_number = 'No response packet.'
            else:
                delta_time = round(response_cap_timestamp_mill - request_cap_timestamp_mill, 2)
                header_string = 'Find target request and response!'
                response_packet_number = self.response_cap_index

            format_dict = dict()
            if self.parse == 'pyshark':
                format_dict = {
                    'header_string': header_string,
                    'filename': self.split_filename,
                    'request_packet_number': self.request_cap_index,
                    'start_time': self.request_cap.frame_info.time,
                    'ip_id': self.request_cap.ip.id,
                    'src_ip': self.request_cap.ip.src,
                    'src_port': self.request_cap.tcp.srcport,
                    'dst_ip': self.request_cap.ip.dst,
                    'dst_port': self.request_cap.tcp.dstport,
                    'response_packet_number': response_packet_number,
                    'delta_time': delta_time,
                    'redis_command': self.request_cap[self.L7_PROTOCOL_NAME.lower()]
                }
            elif self.parse == 'scapy':
                format_dict = {
                    'header_string': header_string,
                    'filename': self.split_filename,
                    'request_packet_number': self.request_cap_index,
                    'start_time': Utils.timstamp2timestring(timestamp=self.request_cap.time),
                    'ip_id': self.request_cap['IP'].id,
                    'src_ip': self.request_cap['IP'].src,
                    'src_port': self.request_cap['TCP'].sport,
                    'dst_ip': self.request_cap['IP'].dst,
                    'dst_port': self.request_cap['TCP'].dport,
                    'response_packet_number': response_packet_number,
                    'delta_time': delta_time,
                    'redis_command': str(self.request_cap['TCP'].payload.load)
                }
            elif self.parse == 'dpkt':
                format_dict = {
                    'header_string': header_string,
                    'filename': self.split_filename,
                    'request_packet_number': self.request_cap_index,
                    'start_time': Utils.timstamp2timestring(timestamp=self.request_cap['timestamp']),
                    'ip_id': self.request_cap['ip'].id,
                    'src_ip': socket.inet_ntoa(self.request_cap['ip'].src),
                    'src_port': self.request_cap['tcp'].sport,
                    'dst_ip': socket.inet_ntoa(self.request_cap['ip'].dst),
                    'dst_port': self.request_cap['tcp'].dport,
                    'response_packet_number': response_packet_number,
                    'delta_time': delta_time,
                    'redis_command': str(self.request_cap['data'])
                }
            else:
                raise Exception()

            output_format_string = """{header_string}
File:{filename}
Request packet number is {request_packet_number}.
Request time is {start_time}
Request packet ip.id is {ip_id}
{src_ip}:{src_port}--->{dst_ip}:{dst_port}
Response packet number is {response_packet_number}
Response packet delta time is {delta_time} ms
Redis command is {redis_command}"""
            self.write_log_info(output_format_string.format(**format_dict) + '\n')
        # 做一下善后工作，清除所有的临时变量
        self.request_cap = None
        self.response_cap = None


def getargs():
    parser = argparse.ArgumentParser(
        description='A tiny tool to analyse capture file under redis protocol.')

    # 指定parser 废弃不用，固定使用dpkt
    # parser.add_argument('--parser', dest='parser', help='set parser type.', type=str,
    #                     choices=['dpkt', 'pyshark', 'scapy'], required=True)

    # 指定超时阈值，单位毫秒
    parser.add_argument('-t', '--timeout-threshold', dest='timeout_threshold',
                        help="Set a timeout threshold between request and response.Unit:msec",
                        type=float,
                        required=True)

    # 设定输出文件名
    parser.add_argument('-o', '--output', dest='output_filename', help='set output filename', type=str, required=True)

    # 是否设置为调试模式
    parser.add_argument('-d', dest='debug', help="set to debug mode(may output MANY logs)", action='store_true')

    # 设定抓包文件名
    parser.add_argument('capture_filename', nargs=1, action='store', help='input capture file')

    return parser.parse_args()


if __name__ == '__main__':
    args = getargs()
    a = redis_analyzer(args.capture_filename[0], args.timeout_threshold, args.output_filename, debug=args.debug)

    a.initial()
    a.go()
