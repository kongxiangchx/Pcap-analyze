#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include <map>
#include "define.h"
using namespace std;

void match_http(char *http_content, int http_len, char *head, char *tail); //匹配http报文
map<u_int16, char *> Init_Cipher_Suites_Table();                           //初始化Cipher_Suites_Table

int main(int argc, char *argv[])
{
    if (argc < 1)
    {
        return 0;
    }
    char file_input[1024];
    char file_output[1024];
    strcpy(file_input, argv[1]);
    strcpy(file_output, argv[2]);

    freopen(file_output, "w", stdout);
    struct pcap_file_header *file_header;
    struct pcap_pkthdr *ptk_header;
    FramHeader_t *mac_header;
    IPHeader_t *ip_header;
    TCPHeader_t *tcp_header;
    UDPHeader_t *udp_header;
    DNSHeader_t *dns_header;

    FILE *fp, *output;
    int pkt_offset, i = 0;
    int ip_len, http_len, ip_proto, dns_len;

    int src_port, dst_port, tcp_flags;

    char my_time[STRSIZE];
    char src_ip[STRSIZE], dst_ip[STRSIZE];

    map<u_int16, char *> cipher_suites_table = Init_Cipher_Suites_Table();

    //初始化
    ptk_header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    mac_header = (FramHeader_t *)malloc(sizeof(FramHeader_t));
    ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
    tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));
    udp_header = (UDPHeader_t *)malloc(sizeof(UDPHeader_t));
    dns_header = (DNSHeader_t *)malloc(sizeof(DNSHeader_t));

    printf("pcap包解析结果: \n");

    if ((fp = fopen(file_input, "rb")) == NULL)
    {
        printf("error: Can not open pcap file\n");
        exit(0);
    }

    //开始读数据包
    pkt_offset = 24; // pcap文件头结构 24个字节

    while (fseek(fp, pkt_offset, SEEK_SET) == 0) //遍历数据包
    {
        i++;
        // pcap_pkt_header 16 byte
        memset(ptk_header, 0, sizeof(struct pcap_pkthdr));
        if (fread(ptk_header, 16, 1, fp) != 1) //读pcap数据包头结构
        {
            printf("\nread end of pcap file\n");
            break;
        }

        printf("\n-----------------------------------\n");
        printf("ID: %d\n", i);

        pkt_offset += 16 + ptk_header->caplen; //下一个数据包的偏移值

        //读取pcap包时间戳，转换成标准格式时间
        struct tm *timeinfo;
        time_t t = (time_t)(ptk_header->ts.tv_sec);
        timeinfo = localtime(&t);

        strftime(my_time, sizeof(my_time), "%Y-%m-%d %H:%M:%S", timeinfo); //获取时间

        printf("-----------------------------------\n");
        printf("链路层\n");

        //数据帧头 14字节
        memset(mac_header, 0, sizeof(FramHeader_t));
        if (fread(mac_header, sizeof(FramHeader_t), 1, fp) != 1)
        {
            printf("Can not read frame_header\n");
            continue;
        }
        printf("Src Mac: ");
        for (int j = 0; j < 6; j++)
        {
            if (j)
            {
                printf(":");
            }
            printf("%02x", mac_header->SrcMAC[j]);
        }
        printf("\n");
        printf("Dst Mac: ");
        for (int j = 0; j < 6; j++)
        {
            if (j)
            {
                printf(":");
            }
            printf("%02x", mac_header->DstMAC[j]);
        }
        printf("\nType: 0x%02x", mac_header->FrameType);
        if (mac_header->FrameType == 8)
        {
            printf(" (IPv4)");
        }
        printf("\n");

        printf("-----------------------------------\n");
        printf("网络层\n");

        // IP数据报头 20字节
        memset(ip_header, 0, sizeof(IPHeader_t));
        if (fread(ip_header, sizeof(IPHeader_t), 1, fp) != 1)
        {
            printf("Can not read ip_header\n");
            continue;
        }

        inet_ntop(AF_INET, (void *)&(ip_header->SrcIP), src_ip, 16);
        inet_ntop(AF_INET, (void *)&(ip_header->DstIP), dst_ip, 16);

        ip_proto = ip_header->Protocol;

        printf("Time: %s\nSrc IP: %s\nDst IP: %s\nIp Protocol: %d\n", my_time, src_ip, dst_ip, ip_proto);
        ip_len = ntohs(ip_header->TotalLen); // IP数据报总长度

        if (ip_proto == 6)
        {
            printf("-----------------------------------\n");
            printf("数据层\n");

            printf("TCP:\n");
            // TCP头 20字节
            if (fread(tcp_header, sizeof(TCPHeader_t), 1, fp) != 1)
            {
                printf("Can not read tcp_header\n");
                continue;
            }
            src_port = ntohs(tcp_header->SrcPort);
            dst_port = ntohs(tcp_header->DstPort);
            tcp_flags = tcp_header->Flags;
            printf("Src Port: %d\nDst Port: %d\nFlag: 0x%02x\n", src_port, dst_port, tcp_flags);

            if (tcp_flags)
            {
                char flag_name[6][10] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"};
                int k = 0;
                printf("[");
                int tmp = tcp_flags;
                while (tmp)
                {
                    int a = tmp % 2;
                    tmp /= 2;
                    if (a == 1)
                    {
                        printf("%s, ", flag_name[k]);
                    }
                    k++;
                }
                printf("]\n");
            }

            if (tcp_flags == 24) // (PSH, ACK) 3路握手成功后
            {
                if (dst_port == 80 || src_port == 80)
                {
                    printf("-----------------------------------\n");
                    printf("应用层\n");
                    http_len = ip_len - 40; // http 报文长度
                    u_int8 http_content_ascii[10000];
                    char http_content[10000];
                    memset(http_content_ascii, 0, sizeof(u_int8));
                    if (fread(http_content_ascii, sizeof(u_int8), http_len, fp) != http_len)
                    {
                        printf("Can not read http_header\n");
                        continue;
                    }
                    for (int j = 0; j < http_len; j++)
                    {
                        http_content[j] = (char)http_content_ascii[j];
                    }

                    if (dst_port == 80)
                    { // request
                        printf("HTTP(request):\n");
                        match_http(http_content, http_len, (char *)"GET", (char *)"\r\n");
                        match_http(http_content, http_len, (char *)"Connection", (char *)"\r\n");
                        match_http(http_content, http_len, (char *)"Accept", (char *)"\r\n");
                        match_http(http_content, http_len, (char *)"User-Agent", (char *)"\r\n");
                        match_http(http_content, http_len, (char *)"Host", (char *)"\r\n");
                    }
                    else if (src_port == 80)
                    { // response
                        printf("HTTP(response):\n");
                        match_http(http_content, http_len, (char *)"HTTP", (char *)"\r\n");
                        match_http(http_content, http_len, (char *)"Connection", (char *)"\r\n");
                        match_http(http_content, http_len, (char *)"Accept", (char *)"\r\n");
                        match_http(http_content, http_len, (char *)"User-Agent", (char *)"\r\n");
                        match_http(http_content, http_len, (char *)"Host", (char *)"\r\n");
                    }
                }
                else if (dst_port == 443)
                { // TLS
                    u_int8 *content_type;
                    u_int8 *handshake_type;
                    content_type = (u_int8 *)malloc(sizeof(u_int8));
                    handshake_type = (u_int8 *)malloc(sizeof(u_int8));
                    fread(content_type, sizeof(u_int8), 1, fp);
                    fseek(fp, 4, SEEK_CUR);
                    fread(handshake_type, sizeof(u_int8), 1, fp);
                    // printf("%d %d\n", *content_type, *handshake_type);
                    if ((*content_type) == 22 && (*handshake_type) == 1)
                    { // Client Hello
                        printf("-----------------------------------\n");
                        printf("应用层\n");
                        printf("TLS:\n");
                        printf("Client Hello\n");

                        fseek(fp, 37, SEEK_CUR);
                        u_int8 *session_id_length;
                        session_id_length = (u_int8 *)malloc(sizeof(u_int8));
                        fread(session_id_length, sizeof(u_int8), 1, fp);

                        fseek(fp, *session_id_length, SEEK_CUR);

                        u_int16 *cipher_suites_length;
                        cipher_suites_length = (u_int16 *)malloc(sizeof(u_int16));
                        fread(cipher_suites_length, sizeof(u_int16), 1, fp);

                        int cipher_suites_nums = ntohs(*cipher_suites_length) / 2;
                        printf("cipher_suites_nums: %d\n", cipher_suites_nums);

                        u_int16 cipher_suites[1000];
                        if (fread(cipher_suites, sizeof(u_int16), cipher_suites_nums, fp) != cipher_suites_nums)
                        {
                            printf("Can not read cipher_suites\n");
                            continue;
                        }
                        for (int j = 0; j < cipher_suites_nums; j++)
                        {
                            cipher_suites[j] = ntohs(cipher_suites[j]);
                            if (cipher_suites_table.count(cipher_suites[j]))
                            {
                                printf("Cipher Suite: %s (0x%04x)\n", cipher_suites_table[cipher_suites[j]], cipher_suites[j]);
                            }
                            else
                            {
                                printf("Cipher Suite: (0x%04x) Not Found\n", cipher_suites[j]);
                            }
                        }

                        u_int8 *comp_methods_length;
                        comp_methods_length = (u_int8 *)malloc(sizeof(u_int8));
                        fread(comp_methods_length, sizeof(u_int8), 1, fp);

                        fseek(fp, (*comp_methods_length) + 2, SEEK_CUR);

                        u_int16 *extension_type;
                        u_int16 *extension_len;
                        extension_type = (u_int16 *)malloc(sizeof(u_int16));
                        extension_len = (u_int16 *)malloc(sizeof(u_int16));
                        while (fread(extension_type, sizeof(u_int16), 1, fp) == 1)
                        {
                            fread(extension_len, sizeof(u_int16), 1, fp);
                            *extension_type = ntohs(*extension_type);
                            *extension_len = ntohs(*extension_len);

                            if ((*extension_type) == 0)
                            {
                                fseek(fp, 5, SEEK_CUR);
                                *extension_len -= 5;
                                u_int8 server_name_ascii[100];
                                if (fread(server_name_ascii, sizeof(u_int8), *extension_len, fp) != *extension_len)
                                {
                                    printf("Can not read extensions_server_name\n");
                                    break;
                                }

                                printf("extensions_server_name: ");
                                for (int j = 0; j < *extension_len; j++)
                                {
                                    printf("%c", (char)server_name_ascii[j]);
                                }
                                printf("\n");
                                break;
                            }
                            else
                            {
                                fseek(fp, (*extension_len), SEEK_CUR);
                            }
                        }
                    }
                }
            }
        }
        else if (ip_proto == 17)
        {
            printf("-----------------------------------\n");
            printf("数据层\n");
            printf("UDP:\n");
            // UDP头 8字节
            if (fread(udp_header, sizeof(UDPHeader_t), 1, fp) != 1)
            {
                printf("Can not read udp_header\n");
                continue;
            }
            src_port = ntohs(udp_header->SrcPort);
            dst_port = ntohs(udp_header->DstPort);
            int udp_len = ntohs(udp_header->Len);
            int udp_checksum = ntohs(udp_header->Checksum);
            printf("Src Port: %d\nDst Port: %d\nLen: %d\nCheckSum: 0x%04x\n", src_port, dst_port, udp_len, udp_checksum);

            //DNS
            if (src_port == 53 || dst_port == 53)
            {
                printf("-----------------------------------\n");
                printf("应用层\n");
                printf("DNS:\n");
                dns_len = ip_len - 28 - 12; // dns 报文长度

                if (fread(dns_header, sizeof(DNSHeader_t), 1, fp) != 1)
                {
                    printf("Can not read dns_header\n");
                    continue;
                }
                u_int16 TransactionID = ntohs(dns_header->TransactionID);
                u_int16 Questions = ntohs(dns_header->Questions);
                u_int16 AnswerRRs = ntohs(dns_header->AnswerRRs);

                printf("TransactionID: 0x%04x\nQuestions: %d\nAnswerRRs: %d\n", TransactionID, Questions, AnswerRRs);

                u_int8 dns_content_ascii[10000];
                char dns_content[10000];
                memset(dns_content_ascii, 0, sizeof(u_int8));
                if (fread(dns_content_ascii, sizeof(u_int8), dns_len, fp) != dns_len)
                {
                    printf("Can not read dns_header\n");
                    continue;
                }
                int p = 0;
                bool flag = true;
                for (int j = 0; j < dns_len; j++)
                {
                    dns_content[j] = (char)dns_content_ascii[j];
                    if (isprint(dns_content_ascii[j]) == 0)
                    {
                        if (flag)
                        {
                            flag = false;
                        }
                        else
                        {
                            p = j;
                            break;
                        }
                    }
                    else
                    {
                        flag = true;
                    }
                }
                printf("Domain Name: ");
                for (int j = 1; j < p - 1; j++)
                {
                    if (isprint(dns_content_ascii[j]))
                    {
                        printf("%c", dns_content[j]);
                    }
                    else
                    {
                        printf(".");
                    }
                }
                printf("\n");
                if (AnswerRRs)
                {
                    printf("Answer IP: ");
                    for (int j = 0; j < 4; j++)
                    {
                        if (j)
                        {
                            printf(".");
                        }
                        printf("%d", dns_content_ascii[j + dns_len - 4]);
                    }
                    printf("\n");
                }
            }
        }
    }

    fclose(fp);
    free(ptk_header);
    free(ip_header);
    free(tcp_header);
    return 0;
}

void match_http(char *http_content, int http_len, char *head, char *tail)
{
    int head_len = strlen(head);
    int tail_len = strlen(tail);
    int i = 0;
    int j = 0;
    int head_pos = -1, tail_pos = -1;
    for (; i < http_len;)
    {
        if (http_content[i] == head[j])
        {
            i++;
            j++;
            if (head_len == j)
            {
                head_pos = i;
                break;
            }
        }
        else
        {
            i = i - j + 1;
            j = 0;
        }
    }

    j = 0;
    for (; i < http_len;)
    {
        if (http_content[i] == tail[j])
        {
            i++;
            j++;
            if (tail_len == j)
            {
                tail_pos = i - 3;
                break;
            }
        }
        else
        {
            i = i - j + 1;
            j = 0;
        }
    }
    if (head_pos != -1 && tail_pos != -1)
    {
        printf("%s", head);
        for (int p = head_pos; p <= tail_pos; p++)
        {
            printf("%c", http_content[p]);
        }
        printf("\n");
    }
    else
    {
        printf("%s: None\n", head);
    }
}

map<u_int16, char *> Init_Cipher_Suites_Table() // TLS1.2
{
    map<u_int16, char *> cipher_suites_table;
    cipher_suites_table.insert(make_pair(0xC02F, (char *)"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));
    cipher_suites_table.insert(make_pair(0xC027, (char *)"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"));
    cipher_suites_table.insert(make_pair(0xC013, (char *)"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0xC030, (char *)"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"));
    cipher_suites_table.insert(make_pair(0xC028, (char *)"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"));
    cipher_suites_table.insert(make_pair(0xC014, (char *)"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0xC061, (char *)"TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"));
    cipher_suites_table.insert(make_pair(0xC060, (char *)"TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"));
    cipher_suites_table.insert(make_pair(0xC077, (char *)"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"));
    cipher_suites_table.insert(make_pair(0xC076, (char *)"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"));
    cipher_suites_table.insert(make_pair(0x9D, (char *)"TLS_RSA_WITH_AES_256_GCM_SHA384"));
    cipher_suites_table.insert(make_pair(0xC0A1, (char *)"TLS_RSA_WITH_AES_256_CCM_8"));
    cipher_suites_table.insert(make_pair(0xC09D, (char *)"TLS_RSA_WITH_AES_256_CCM"));
    cipher_suites_table.insert(make_pair(0xC051, (char *)"TLS_RSA_WITH_ARIA_256_GCM_SHA384"));
    cipher_suites_table.insert(make_pair(0x9C, (char *)"TLS_RSA_WITH_AES_128_GCM_SHA256"));
    cipher_suites_table.insert(make_pair(0xC0A0, (char *)"TLS_RSA_WITH_AES_128_CCM_8"));
    cipher_suites_table.insert(make_pair(0xC02C, (char *)"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"));
    cipher_suites_table.insert(make_pair(0xC09C, (char *)"TLS_RSA_WITH_AES_128_CCM"));
    cipher_suites_table.insert(make_pair(0xC050, (char *)"TLS_RSA_WITH_ARIA_128_GCM_SHA256"));
    cipher_suites_table.insert(make_pair(0x3D, (char *)"TLS_RSA_WITH_AES_256_CBC_SHA256"));
    cipher_suites_table.insert(make_pair(0xC0, (char *)"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"));
    cipher_suites_table.insert(make_pair(0x3C, (char *)"TLS_RSA_WITH_AES_128_CBC_SHA256"));
    cipher_suites_table.insert(make_pair(0xBA, (char *)"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"));
    cipher_suites_table.insert(make_pair(0x35, (char *)"TLS_RSA_WITH_AES_256_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0x84, (char *)"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0x2F, (char *)"TLS_RSA_WITH_AES_128_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0x96, (char *)"TLS_RSA_WITH_SEED_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0x41, (char *)"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0xCCA8, (char *)"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"));
    cipher_suites_table.insert(make_pair(0xC02B, (char *)"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"));
    cipher_suites_table.insert(make_pair(0xCCA9, (char *)"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"));
    cipher_suites_table.insert(make_pair(0xC009, (char *)"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0xC00A, (char *)"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0xA, (char *)"TLS_RSA_WITH_3DES_EDE_CBC_SHA"));
    cipher_suites_table.insert(make_pair(0xc023, (char *)"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"));
    cipher_suites_table.insert(make_pair(0xc028, (char *)"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"));
    cipher_suites_table.insert(make_pair(0xc024, (char *)"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"));
    cipher_suites_table.insert(make_pair(0x1301, (char *)"TLS_AES_128_GCM_SHA256"));
    cipher_suites_table.insert(make_pair(0x1302, (char *)"TLS_AES_256_GCM_SHA384"));
    cipher_suites_table.insert(make_pair(0x1303, (char *)"TLS_CHACHA20_POLY1305_SHA256"));

    return cipher_suites_table;
}