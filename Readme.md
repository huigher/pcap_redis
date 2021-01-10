# 脚本主要功能
传入一个抓包文件，分析其中每一条TCP流，是否有发出请求后，远端Redis实例响应慢的情况

# 脚本会做的事情
1. 调用第三方工具PcapPlusPlus将抓包文件以TCP流为单位，拆分成若干文件，存放于/tmp/{uuid}目录下
2. 轮询所有的抓包文件，对每一条TCP流进行分析，确认是否出现问题现场
3、将结果输出至脚本同目录下的文件,输出的文件名通过传参指定
   
# 文件结构
- `main.py`，主文件，绝大部分逻辑都在这里实现
- `Utils.py`，一些通用的工具方法会放在这个文件里
- `test.py`，作者天马行空的测试文件，大家可以忽略

# 参数说明
可通过传入-h参数来获得参数的详细说明，以下挑选关键参数说明：
```
usage: main.py [-h] [--parser {dpkt,pyshark,scapy}] -t TIMEOUT_THRESHOLD
               [-o OUTPUT_FILENAME] [-d]
               capture_filename
--parser 指定pcap文件的分析器，推荐使用dpkt，非常高效。注意，scapy分析器解pcap包似乎有些问题，暂不推荐使用
-t 设定超时时间，单位为毫秒
-o 设定分析结果输出的文件名
-d 设定为debug模式，该模式下输出文件会非常丰富，一般用于调试用
```

# 目前可以诊断的问题现场
1. 客户端发出Redis请求命令后，远端回复响应时间超过阈值时
2. 客户端发出Redis请求命令后，在整个TCP流中，没有得到远端的响应
注：上述的请求、响应均值Redis协议层，即TCP层不带payload的ACK包不会被认为是"响应"

# 特别感谢
[PcapPlusPlus](https://pcapplusplus.github.io/) : 以非常高效的性能将一个pcap文件以TCP流为单位，拆分成若干文件

# 最后
作者时间有限，咱没有搞定PcapPlusPlus的跨平台编译，暂没有深究如何可以将拆包这个动作做成平台无关（主要是PcapPlusPlus在不同系统中的运行依赖），现在是以一个不太优雅的方式实现：直接在项目中引用了PcapPlusPlus在MacOS下的二进制文件 Orz