#ifndef DEFINE_H
#define DEFINE_H
#include <stdlib.h>

#define STRSIZE 1024

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;
typedef u_int16_t u_short;
typedef u_int32_t u_int32;
typedef u_int16_t u_int16;
typedef u_int8_t u_int8;

// pacp文件头结构体

struct pcap_file_header
{
    bpf_u_int32 magic;     /* 0xD4C3B2A1 */
    u_short version_major; /* magjor Version 2 */
    u_short version_minor; /* magjor Version 4 */
    bpf_int32 thiszone;    /* gmt to local correction */
    bpf_u_int32 sigfigs;   /* accuracy of timestamps */
    bpf_u_int32 snaplen;   /* max length saved portion of each pkt */
    bpf_u_int32 linktype;  /* data link type (LINKTYPE_*) */
};

//时间戳
struct time_val
{
    int tv_sec;  /* seconds 含义同 time_t 对象的值 */
    int tv_usec; /* and microseconds */
};

// pcap数据包头结构体
struct pcap_pkthdr
{
    struct time_val ts; /* time stamp */
    bpf_u_int32 caplen; /* length of portion present */
    bpf_u_int32 len;    /* length this packet (off wire) */
};

//数据帧头
typedef struct FramHeader_t
{                      // Pcap捕获的数据帧头
    u_int8 DstMAC[6];  //目的MAC地址
    u_int8 SrcMAC[6];  //源MAC地址
    u_short FrameType; //帧类型
} FramHeader_t;

// IP数据报头
typedef struct IPHeader_t
{                         // IP数据报头
    u_int8 Ver_HLen;      //版本+报头长度
    u_int8 TOS;           //服务类型
    u_int16 TotalLen;     //总长度
    u_int16 ID;           //标识
    u_int16 Flag_Segment; //标志+片偏移
    u_int8 TTL;           //生存周期
    u_int8 Protocol;      //协议类型
    u_int16 Checksum;     //头部校验和
    u_int32 SrcIP;        //源IP地址
    u_int32 DstIP;        //目的IP地址
} IPHeader_t;

// TCP数据报头
typedef struct TCPHeader_t
{                          // TCP数据报头
    u_int16 SrcPort;       //源端口
    u_int16 DstPort;       //目的端口
    u_int32 SeqNO;         //序号
    u_int32 AckNO;         //确认号
    u_int8 HeaderLen;      //数据报头的长度(4 bit) + 保留(4 bit)
    u_int8 Flags;          //标识TCP不同的控制消息
    u_int16 Window;        //窗口大小
    u_int16 Checksum;      //校验和
    u_int16 UrgentPointer; //紧急指针
} TCPHeader_t;

typedef struct UDPHeader_t
{
    u_int16 SrcPort;
    u_int16 DstPort;
    u_int16 Len;
    u_int16 Checksum;
} UDPHeader_t;

typedef struct DNSHeader_t
{
    u_int16 TransactionID;
    u_int16 Flags;
    u_int16 Questions;
    u_int16 AnswerRRs;
    u_int16 AuthRRs;
    u_int16 AddRRs;
} DNSHeader_t;

#endif // DEFINE_H