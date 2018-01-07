#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#include "checksum.h"

typedef struct ping_packet_status {
    struct timeval begin_time;
    struct timeval end_time;
    int flag;   //发送标志,1为已发送
    int seq;     //包的序列号
} ping_packet_status;

#define PACKET_SEND_MAX_NUM 64
struct sockaddr_in dest;
unsigned int addr = 1;
pid_t pid;
int alive;
int send_count;
int recv_count;
struct timeval start_time;
struct timeval end_time;
struct timeval time_interval;
ping_packet_status ping_packet[PACKET_SEND_MAX_NUM];
int rawsock;

struct timeval cal_time_offset(struct timeval begin, struct timeval end) {
    struct timeval ans;
    ans.tv_sec = end.tv_sec - begin.tv_sec;
    ans.tv_usec = end.tv_usec - begin.tv_usec;
    if (ans.tv_usec < 0) //如果接收时间的usec小于发送时间的usec，则向sec域借位
    {
        ans.tv_sec--;
        ans.tv_usec += 1000000;
    }
    return ans;
}

void pack(struct icmp* icmp_packet, int seq, int length) {
    icmp_packet->icmp_type = ICMP_ECHO;
    icmp_packet->icmp_code = 0;
    icmp_packet->icmp_cksum = 0;
    icmp_packet->icmp_seq = seq;
    icmp_packet->icmp_id = pid &0xffff;
    for (int i=0;i<length;i++){
        icmp_packet->icmp_data[i]=i;
    }
    icmp_packet->icmp_cksum = cal_chksum((unsigned short*) icmp_packet, length);
}

int unpack(char* buf, int len) {
    int iphdr_len;
    struct timeval begin_time, recv_time, offset_time;
    int rtt;  //round trip time

    struct ip* ip_hdr = (struct ip*) buf;
    iphdr_len = ip_hdr->ip_hl * 4;
    struct icmp* icmp = (struct icmp*) (buf + iphdr_len);
    len -= iphdr_len;  //icmp包长度
    if (len < 8)   //判断长度是否为ICMP包长度
    {
        fprintf(stderr, "Invalid icmp packet.Its length is less than 8\n");
        return -1;
    }

    //判断该包是ICMP回送回答包且该包是我们发出去的
    if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == (pid & 0xffff))) {
        if ((icmp->icmp_seq < 0) || (icmp->icmp_seq > PACKET_SEND_MAX_NUM)) {
            fprintf(stderr, "icmp packet seq is out of range!\n");
            return -1;
        }

        ping_packet[icmp->icmp_seq].flag = 0;
        begin_time = ping_packet[icmp->icmp_seq].begin_time;
        gettimeofday(&recv_time, NULL);

        offset_time = cal_time_offset(begin_time, recv_time);
        rtt = offset_time.tv_sec * 1000 + offset_time.tv_usec / 1000; //毫秒为单位

        printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%d ms\n",
               len, inet_ntoa(ip_hdr->ip_src), icmp->icmp_seq, ip_hdr->ip_ttl, rtt);

    } else {
        fprintf(stderr, "Invalid ICMP packet! Its id is not matched!\n");
        return -1;
    }
    return 0;
}

void ping_send() {
    char send_buf[128];
    memset(send_buf, 0, sizeof(send_buf));
    gettimeofday(&start_time, NULL); //记录第一个ping包发出的时间
    while (alive) {
        int size = 0;
        gettimeofday(&(ping_packet[send_count].begin_time), NULL);
        ping_packet[send_count].flag = 1; //将该标记为设置为该包已发送

        pack((struct icmp*) send_buf, send_count, 64); //封装icmp包
        size = sendto(rawsock, send_buf, 64, 0, (struct sockaddr*) &dest, sizeof(dest));
        send_count++; //记录发出ping包的数量
        if (size < 0) {
            fprintf(stderr, "send icmp packet fail!\n");
            continue;
        }

        sleep(1);
    }
}

void ping_recv() {
    struct timeval tv;
    tv.tv_usec = 200;  //设置select函数的超时时间为200us
    tv.tv_sec = 0;
    fd_set read_fd;
    char recv_buf[512];
    memset(recv_buf, 0, sizeof(recv_buf));
    while (alive) {
        int ret = 0;
        FD_ZERO(&read_fd);
        FD_SET(rawsock, &read_fd);
        ret = select(rawsock + 1, &read_fd, NULL, NULL, &tv);
        switch (ret) {
            case -1:
                printf(stderr, "fail to select!\n");
                break;
            case 0:
                break;
            default: {
                int size = recv(rawsock, recv_buf, sizeof(recv_buf), 0);
                if (size < 0) {
                    printf(stderr, "recv data fail!\n");
                    continue;
                }

                ret = unpack(recv_buf, size); //对接收的包进行解封
                if (ret == -1)  //不是属于自己的icmp包，丢弃不处理
                {
                    continue;
                }
                recv_count++; //接收包计数
            }
                break;
        }

    }
}

void icmp_sigint(int signo) {
    alive = 0;
    gettimeofday(&end_time, NULL);
    time_interval = cal_time_offset(start_time, end_time);
}

void ping_stats_show() {
    long time = time_interval.tv_sec * 1000 + time_interval.tv_usec / 1000;
    /*注意除数不能为零，这里send_count有可能为零，所以运行时提示错误*/
    printf("%d packets transmitted, %d recieved, %d%c packet loss, time %ldms\n",
           send_count, recv_count, (send_count - recv_count) * 100 / send_count, '%', time);
}
int main(int argc, char* argv[]) {
    char args[100];
    int size = 128 * 1024;
    char dest_hostname[64];//域名最大长度为63
    struct protoent* protocol = NULL;
    struct hostent* host = NULL;
    pthread_t send_id, recv_id;
    memset(dest_hostname, 0, 64);
    if (argc < 2) {
        printf("请指定要ping的地址！\n");
        return 0;
    }
    if (strlen(argv[1]) > 63) {
        printf("请输入正确的地址！\n");
        return 0;
    }
    strcpy(dest_hostname, argv[1]);
    protocol = getprotobyname("icmp");
    if (protocol == NULL) {
        printf("获取protocol失败！\n");
    }
    rawsock = socket(AF_INET, SOCK_RAW, protocol->p_proto);
    if (rawsock == 0) {
        printf("创建socket失败\n");
        return 0;
    }
    setsockopt(rawsock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    addr = inet_addr(dest_hostname);
    if (addr == INADDR_NONE) {
        host = gethostbyname(dest_hostname);
        if (host == NULL) {
            printf("找不到该域名！\n");
            return 0;
        }
        memcpy((char*) &(dest.sin_addr), host->h_addr, host->h_length);
    } else {
        memcpy((char*) &(dest.sin_addr), &addr, sizeof(addr));
    }
    //ip地址转换为长整形时是反向储存的，如192.168.1.1 储存为192x1+168x256+1*256*256+256*256*256=16885952
    printf("Ping %s,(%d.%d.%d.%d) 56(84) bytes of data.\n",
           dest_hostname,
           (dest.sin_addr.s_addr & 0x000000ff),
           (dest.sin_addr.s_addr & 0x0000ff00) >> 8,
           (dest.sin_addr.s_addr & 0x00ff0000) >> 16,
           (dest.sin_addr.s_addr & 0xff000000) >> 24);

    alive = 1;  //控制ping的发送和接收

    signal(SIGINT, icmp_sigint);

    if (pthread_create(&send_id, NULL, (void*) ping_send, NULL)) {
        printf("Fail to create ping send thread!\n");
        return -1;
    }

    if (pthread_create(&recv_id, NULL, (void*) ping_recv, NULL)) {
        printf("Fail to create ping recv thread!\n");
        return -1;
    }

    pthread_join(send_id, NULL);//等待send ping线程结束后进程再结束
    pthread_join(recv_id, NULL);//等待recv ping线程结束后进程再结束

    ping_stats_show();

    close(rawsock);
    return 0;
}