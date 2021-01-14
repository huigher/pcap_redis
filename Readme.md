# 运行环境说明
- 运行环境为python3.6+
- Windows下需要winpcap工具，下载地址：https://www.winpcap.org/install/default.htm
- python第三方包依赖可以参考文件requirements.txt，可以使用pip直接安装(`pip install -r requirements.txt`)或使用python虚拟环境来安装

# 脚本主要功能
传入一个抓包文件，分析其中每一条TCP流，是否有发出请求后，远端Redis实例响应慢的情况

# 脚本会做的事情
1. 调用第三方工具PcapPlusPlus将抓包文件以TCP流为单位，拆分成若干文件，存放于临时文件夹下，根据操作系统不同会放在不同的目标，
   一般来说Linux是`/tmp`，Windows是`C:\Users\${Username}\AppData\Local\Temp`，MacOS是`/var/folders/`下的某个目录
2. 轮询所有的抓包文件，对每一条TCP流进行分析，确认是否出现问题现场
3. 将结果输出至脚本同目录下的文件,输出的文件名通过传参指定

# 文件结构
- `main.py`，主文件，绝大部分逻辑都在这里实现
- `Utils.py`，一些通用的工具方法会放在这个文件里
- `test.py`，作者天马行空的测试文件，大家可以忽略

# 参数说明
可通过传入-h参数来获得参数的详细说明，以下挑选关键参数说明：
```
usage: main.py [-h] -t TIMEOUT_THRESHOLD [-o OUTPUT_FILENAME] [-d]
               capture_filename
-t 设定超时时间，单位为毫秒
-o 设定分析结果输出的文件名
-d 设定为debug模式，该模式下输出文件会非常丰富，一般用于调试用
```
命令举例：`python main.py redis.pcap -o redis.example.100ms.info -t 100`
```
释义：
分析抓包文件redis.pcap，
设置的超时时间阈值为100毫秒，
将结果输出到文件redis.example.100ms.info中
```

# 目前可以诊断的问题现场
1. 客户端发出Redis请求命令后，远端回复响应时间超过阈值时
2. 客户端发出Redis请求命令后，在整个TCP流中，没有得到远端的响应
注：上述的请求、响应均值Redis协议层，即TCP层不带payload的ACK包不会被认为是"响应"

# 特别感谢
[PcapPlusPlus](https://pcapplusplus.github.io/) : 以非常高效的性能将一个pcap文件以TCP流为单位，拆分成若干文件

# FAQ
Q：在Windows平台下运行出现"无法启动此程序，因为计算机中丢失wpcap.dll"的报错
A：缺少Winpcap组件，可以到以下地址下载安装：https://www.winpcap.org/install/default.htm

# TODO list
1. 现有的场景下，对于以下的特殊场景还需要做适配：
- 存在delay ack的情况，且之后的响应包很快的回复，会导致响应返回的很快的假象，需要计算单纯的远端返回tcp ack包的时间差值
- 对于请求命令非常大的场景，客户端发出的请求报文会被拆分成若干个小的TCP段，目前的逻辑暂时是以最后一个段的时间戳为起始点，若客户端发送这几个数据包有较大的时间差，也会出现计算不准的问题
2. 输出的文件支持json格式，便于二次开发
4. 未来计划加入更多的场景，比如在TCP建连的时候就出现了问题的场景