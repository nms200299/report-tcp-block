#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // exit
#include <string.h> // strlen

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <net/ethernet.h>

#include <sys/socket.h> // socket
#include <sys/ioctl.h> // ioctl
#include <net/if.h> // hw info struct

#pragma pack(push,1)
struct packet_ptr {
    struct ether_header *ep;
    struct ip *iph;
    struct tcphdr *tcph;
};

struct packet_nonptr {
    struct ether_header ep;
    struct ip iph;
    struct tcphdr tcph;
    //char tcpdata[5]= "aaaa";
};
#pragma pack(pop)

struct packet_ptr org_packet;

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
    exit(-1);
}


void send_packet(pcap_t* handle, char* dev, bool forward, int tcpdata_len){
    struct packet_nonptr block_packet;

    printf("tcp data len : %d \n",tcpdata_len);

    int sockfd, ret;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
      printf("Fail to get interface MAC address - socket() failed - %m\n");
      exit(-1);
    }
    // socket

    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    memcpy(block_packet.ep.ether_shost, ifr.ifr_hwaddr.sa_data, 6);
    // my mac

    block_packet.ep.ether_type = htons(ETHERTYPE_IP);
    block_packet.tcph.th_off = 5;
    block_packet.tcph.rst = 1;
    block_packet.tcph.ack = 1;
    block_packet.tcph.syn = 0;
    block_packet.tcph.th_urp = 0;

    block_packet.iph.ip_hl = 5;
    block_packet.iph.ip_v = 4;
    // htons -> reverse
    block_packet.iph.ip_p = IPPROTO_TCP;
    block_packet.iph.ip_off = 0;

    if (forward == true){
        memcpy(block_packet.ep.ether_dhost, org_packet.ep->ether_dhost, 6);
        // ep
        block_packet.iph.ip_len = htons((int)(sizeof(struct ip) + sizeof (struct tcphdr)));
        block_packet.iph.ip_ttl = org_packet.iph->ip_ttl;
        block_packet.iph.ip_dst = org_packet.iph->ip_dst;
        block_packet.iph.ip_src = org_packet.iph->ip_src;
        // iph
        block_packet.tcph.th_sport = org_packet.tcph->th_sport;
        block_packet.tcph.th_dport = org_packet.tcph->th_dport;
        block_packet.tcph.th_seq = htonl(ntohl(org_packet.tcph->th_seq) + tcpdata_len);
        block_packet.tcph.th_ack = org_packet.tcph->th_ack;
        // tcph
    } else {
        memcpy(block_packet.ep.ether_dhost, org_packet.ep->ether_shost, 6);
        //ep
        block_packet.iph.ip_len = htons((int)(sizeof(struct ip) + sizeof (struct tcphdr)));//sizeof(block_packet.iph) + sizeof (block_packet.tcph) + sizeof (msg);
        block_packet.iph.ip_ttl = 128;
        block_packet.iph.ip_dst = org_packet.iph->ip_src;
        block_packet.iph.ip_src = org_packet.iph->ip_dst;
        // iph
        block_packet.tcph.th_sport = org_packet.tcph->th_dport;
        block_packet.tcph.th_dport = org_packet.tcph->th_sport;
        block_packet.tcph.th_seq = org_packet.tcph->th_ack;
        block_packet.tcph.th_ack = htonl(ntohl(org_packet.tcph->th_seq) + tcpdata_len);
        // tcph
    }



    u_int16_t temp_chksum=0;
    u_int64_t sum_chksum=0;

    temp_chksum = 0x45 << 8; // block_packet.iph.ip_hl & block_packet.iph.ip_v
    temp_chksum += block_packet.iph.ip_tos;
    sum_chksum += temp_chksum;
    sum_chksum += ntohs(block_packet.iph.ip_len);
    sum_chksum += ntohs(block_packet.iph.ip_id);
    sum_chksum += ntohs(block_packet.iph.ip_off);
    temp_chksum = block_packet.iph.ip_ttl << 8;
    temp_chksum += block_packet.iph.ip_p;
    sum_chksum += temp_chksum;
    sum_chksum += ntohl(block_packet.iph.ip_src.s_addr) >> 16;
    sum_chksum += ntohl(block_packet.iph.ip_src.s_addr) << 16 >> 16;
    sum_chksum += ntohl(block_packet.iph.ip_dst.s_addr) >> 16;
    sum_chksum += ntohl(block_packet.iph.ip_dst.s_addr) << 16 >> 16;
    sum_chksum = (sum_chksum >> 16) + (sum_chksum & 0xffff);
    block_packet.iph.ip_sum = htons(sum_chksum ^ 0xffff);
    // ipv4 hdr checksum

    sum_chksum = 0;
    sum_chksum += ntohl(block_packet.iph.ip_src.s_addr) >> 16;
    sum_chksum += ntohl(block_packet.iph.ip_src.s_addr) << 16 >> 16;
    sum_chksum += ntohl(block_packet.iph.ip_dst.s_addr) >> 16;
    sum_chksum += ntohl(block_packet.iph.ip_dst.s_addr) << 16 >> 16;
    sum_chksum += block_packet.iph.ip_p;
    sum_chksum += sizeof (struct tcphdr);
    temp_chksum = (sum_chksum >> 16) + (sum_chksum & 0xffff);

    sum_chksum = 0;
    sum_chksum += ntohs(block_packet.tcph.th_sport);
    sum_chksum += ntohs(block_packet.tcph.th_dport);
    sum_chksum += ntohl(block_packet.tcph.th_seq) >> 16;
    sum_chksum += ntohl(block_packet.tcph.th_seq) << 16 >> 16;
    sum_chksum += ntohl(block_packet.tcph.th_ack) >> 16;
    sum_chksum += ntohl(block_packet.tcph.th_ack) << 16 >> 16;
    sum_chksum += (block_packet.tcph.th_off << 12) + block_packet.tcph.th_flags;
    sum_chksum += ntohs(block_packet.tcph.th_win);
    sum_chksum = (sum_chksum >> 16) + (sum_chksum & 0xffff);

    sum_chksum += temp_chksum;
    sum_chksum = (sum_chksum >> 16) + (sum_chksum & 0xffff);
    block_packet.tcph.th_sum = htons(sum_chksum ^ 0xffff);
    printf("0x%x \n",block_packet.tcph.th_sum);


    if (pcap_sendpacket(handle, (unsigned char*)&block_packet, sizeof(block_packet)) != 0){
        printf("Packet Send Fail..\n");
        exit (-1);
        // 패킷을 보냄
    }


}


int main(int argc, char* argv[]) {

    if (argc != 3) {
        usage();
    }

    char* dev = argv[1];
    char* rule = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }


    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap_handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap_handle));
            break;
        }

        org_packet.ep = (struct ether_header *)packet;
        // 이더넷 헤더를 구한다.

        if (ntohs(org_packet.ep->ether_type) == ETHERTYPE_IP){
            packet += sizeof(struct ether_header);
            // IP 헤더를 구하기 위해 이더넷 헤더만큼 오프셋.
            org_packet.iph = (struct ip *)packet;

            if (org_packet.iph->ip_p == IPPROTO_TCP){
                org_packet.tcph = (struct tcphdr *)(packet + org_packet.iph->ip_hl * 4);

                int length = header->len - sizeof (* org_packet.ep);
                // length는 총 패킷 크기 - 이더넷 헤더 크기
                // (IP 헤더 크기 + TCP 헤더 크기 + TCP 페이로드 크기)
                int i=(org_packet.iph->ip_hl*4)+(org_packet.tcph->doff*4);
                int payload_len = length-i;
                // i는 IP 헤더 크기 + TCP 헤더 크기
                // length-i를 하면 TCP 페이로드 길이를 구할 수 있음.

                int j=0, sum=0;
                for(; i<length;i++){
                    if (*(packet+i) == *(rule+j)){
                        j++;
                        sum = sum+1;

                        if (strlen(rule) == sum){
                            send_packet(pcap_handle, dev, false, payload_len);
                            send_packet(pcap_handle, dev, true, payload_len);
                            printf("\n****************** Found !!!\n");

                        }
                    } else {
                        j=0;
                        sum = 0;
                    }

                }
            }
        }
    }

    pcap_close(pcap_handle);
}