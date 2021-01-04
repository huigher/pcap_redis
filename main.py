# coding=utf-8
import pyshark
import Utils
import nest_asyncio
import uuid
import os


class redis_analyzer:
    def __init__(self, capture_filename, timeout_threshold, output_filename, debug=False):
        self.capture_filename = capture_filename
        self.timeout_threshold = timeout_threshold
        self.output_filename = output_filename
        self.output_writer = open(output_filename, 'a')
        self.debug = debug

        # 设定一些常数
        self.TCP_STREAM_COUNTS = 99999
        self.REDIS_PORT = 6379
        self.L7_PROTOCOL_NAME = 'redis'

        # 存放一些公共临时参数
        self.request_cap = None
        self.response_cap = None
        # self.tcp_stream_number = None

        # 设定一个临时目录
        self.tmp_folder_name = str(uuid.uuid1())
        self.tmp_folder_path = r'/tmp/' + self.tmp_folder_name + r'/'

    def initial(self):
        nest_asyncio.apply()
        self.split_capture_file()

    def split_capture_file(self):
        self.write_log_info('Start to split capture file,temporarily folder is '+self.tmp_folder_path)
        os.system(r'mkdir '+self.tmp_folder_path)
        f=os.popen(r'bin/PcapSplitter -m connection -f ' + self.capture_filename + ' -o ' + self.tmp_folder_path)
        self.write_log_info('Splitting Finished.Reulst: \n'+f.read())

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
        self.output_writer.write(('=' * 50) + '\n')
        self.write_log_info('Start to analyse,Filename is ' + self.capture_filename)
        self.output_writer.flush()
        # 逐个文件分析
        for path, dir_list, file_list in os.walk(self.tmp_folder_path):
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
                caps = pyshark.FileCapture(self.tmp_folder_path+file_name, keep_packets=False)
                self.write_log_info('已打开抓包文件：' + str(file_name))
                # 设定一个计数器，从1开始
                cap_index = 1
                self.write_log_debug('准备开始迭代过滤后的数据包文件')
                for cap in caps:
                    self.write_log_debug('打开了一个具体的packet，文件名为' + str(file_name) + ',这个packet在流中的序列号为' + str(cap_index))
                    # 设定一些flags
                    is_request = None
                    is_response = None
                    # 给每一个flags置位
                    if int(cap.tcp.dstport) == self.REDIS_PORT and int(
                            cap.tcp.len) > 0 and cap.highest_layer.upper() == self.L7_PROTOCOL_NAME.upper():
                        is_request = True
                        found_request = True
                    else:
                        is_request = False
                    if int(cap.tcp.srcport) == self.REDIS_PORT \
                            and int(cap.tcp.len) > 0 \
                            and cap.highest_layer.upper() == self.L7_PROTOCOL_NAME.upper():
                        is_response = True
                    else:
                        is_response = False

                    if is_request:
                        self.write_log_debug('是一个请求包')
                        if wanna_request:
                            self.request_cap = cap
                            found_request = True
                            wanna_response = True
                            wanna_request = False
                            cap_index += 1
                            continue
                        else:
                            # 应该不会进入到这个逻辑里……
                            self.write_log_warning('进入到了一个不应该进入的条件中！')
                            cap_index += 1
                            continue
                    if is_response:
                        self.write_log_debug('是一个响应包')
                        if wanna_response:
                            # 进入最关键的比对逻辑
                            self.response_cap = cap
                            # self.tcp_stream_number = i
                            self.compare_request_and_response()
                            # 清除一下临时的flags
                            wanna_request = True
                            found_request = False
                            wanna_response = False
                            cap_index += 1
                            continue
                        else:
                            # 可能是每一条流的最开始的响应，或者是孤立的响应报文，忽略
                            cap_index += 1
                            continue
                    # 不是任何感兴趣的包
                    self.write_log_debug('不是感兴趣的包，跳过')
                    cap_index += 1
                self.write_log_debug('抓包文件' + str(file_name) + '已经遍历完毕。')
                caps.close_async()
                # 包里所有的报文都已经遍历完毕，需要处理一下特殊的情况
                if found_request and wanna_response:
                    # 找到了request，但是没有找到任何response
                    self.write_log_debug('找到了一个没有响应的请求包！')
                    # self.tcp_stream_number = i
                    self.compare_request_and_response()

    def compare_request_and_response(self):
        # 先判断一下是否符合记录异常的标准
        is_target_scene = False
        if not self.response_cap:
            # 没有响应报文
            is_target_scene = True
        else:
            # 有响应报文
            if float(self.response_cap.frame_info.time_epoch) * 1000 - float(
                    self.request_cap.frame_info.time_epoch) * 1000 > self.timeout_threshold:
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
                delta_time = float(self.response_cap.frame_info.time_epoch) - float(
                    self.request_cap.frame_info.time_epoch)
                header_string = 'Find target request and response!'
                response_packet_number = self.response_cap.frame_info.number
            format_dict = {
                'header_string': header_string,
                # 'tcp_stream': self.tcp_stream_number,
                'request_packet_number': self.request_cap.frame_info.number,
                'start_time': self.request_cap.frame_info.time,
                'src_ip': self.request_cap.ip.src,
                'src_port': self.request_cap.tcp.srcport,
                'dst_ip': self.request_cap.ip.dst,
                'dst_port': self.request_cap.tcp.dstport,
                'response_packet_number': response_packet_number,
                'delta_time': delta_time,
                'redis_command': self.request_cap[self.L7_PROTOCOL_NAME.lower()]
            }

            output_format_string = """{header_string}
TCP stream is {tcp_stream}.
Request packet number is {request_packet_number}.
Request time is {start_time}
{src_ip}:{src_port}--->{dst_ip}:{dst_port}
Response packet number is {response_packet_number}
Response packet delta time is {delta_time}
Redis command is {redis_command}"""
            self.write_log_info(output_format_string.format(**format_dict) + '\n')
        # 做一下善后工作，清除所有的临时变量
        self.request_cap = None
        self.response_cap = None
        # self.tcp_stream_number = None


if __name__ == '__main__':
    # a = redis_analyzer('include2streams.pcap', 10, 'output.info',debug=True)
    a = redis_analyzer('redis.pcap', 10, 'output.info',debug=False)

    a.initial()
    a.go()
