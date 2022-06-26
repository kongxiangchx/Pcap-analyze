## 简介
本代码在VSCode+Ubuntu子系统下编写，实现了pcap文件分析。

## 实现功能
实现了对链路层、网络层、数据层、应用层信息的读取，其中数据层分析包括TCP、UDP，应用层分析包括DNS、HTTP、TLS。

## 文件解释
- pic：结果展示
- input：pcap文件所在目录
- output：pcap文件的分析结果所在目录
- define.h：宏定义+数据报头对应的结构体定义
- main.cc：pcap文件分析程序，有两个参数，分别为pcap文件名、pcap分析结果文件名
  运行示例：
  g++ -o main.out main.cc
  ./main.out xxx.pcap xxx.txt
- main.sh：执行pcap文件分析程序的脚本，通过遍历文件目录，可以进行目录下所有pcap文件的分析（只能分析单个文件夹下的所有pcap文件）  
  本脚本文件也有两个参数，分别是pcap文件所在目录、pcap文件的分析结果所在目录。
  运行示例：sh main.sh input/xxx output/xxx
- start.sh：执行main.sh脚本的脚本，将所有pcap文件通过pcap文件分析程序进行分析

## 运行步骤
1. 将获取的pcap文件夹放在input文件夹下
2. 更改start.sh脚本，将文件夹名改成自己的
3. 执行start.sh脚本

## 结果展示
- UDP分析结果
<img src="pic\图片1.png" alt="图片1"/>

- TCP分析结果
<img src="pic\图片2.png" alt="图片2"/>

- DNS分析结果
<img src="pic\图片3.png" alt="图片3"/>

- HTTP分析结果
<img src="pic\图片4.png" alt="图片4"/>

- TLS分析结果
<img src="pic\图片5.png" alt="图片5"/>