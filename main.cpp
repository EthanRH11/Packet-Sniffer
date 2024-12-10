#include <iostream>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*To open the device for reading use the function:
        pcap_open_live().
    -This function takes 5 arguments, the device to open and read from
    -The snapshot length
    -Enable/Disable promiscuous mode
    -Packet buffer timeout in milliseconds
    -A buffer to store any errors*/
/*pcap_open_live(): returns a pointer of type pcap_t which will be passed as an argument to
  pcap_loop();*/

/*pcap_loop() takes 4 arguments:
    -Device used to capture packets
    -Number of packets to process
    -Callback function, this is called each time a packet is captured
    -The first argument to pass to the callback function*/
/*pcap_loop(): Will process a number of a packets, if the number is set to 0 or -1 it
  will loop indefinitely or until another condition stops it*/
/*The callback function specifies a pcap_handle which takes 3 arguments:
    -the last argument passed to pcap_loop
    -a pointer to a pcap_pkthdr struct that points to the packet timestamp and lengths
    -a pointer to the packet data*/

int link_hdr_length = 0;

void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packeted_ptr)
{
    packeted_ptr += link_hdr_length;
    struct ip *ip_hdr = (struct ip *)packeted_ptr;

    char packet_scrip[INET_ADDRSTRLEN]; // Source IP address
    char packet_dstip[INET_ADDRSTRLEN]; // Destination IP address
    strcpy(packet_scrip, inet_ntoa(ip_hdr->ip_src));
    strcpy(packet_dstip, inet_ntoa(ip_hdr->ip_dst));
    int packet_id = ntohs(ip_hdr->ip_id),   // Identification
        packet_ttl = ip_hdr->ip_ttl,        // Time to live
        packet_tos = ip_hdr->ip_tos,        // Type of service
        packet_len = ntohs(ip_hdr->ip_len), // Header length + data length
        packet_hlen = ip_hdr->ip_hl;        // Header Length

    printf("************************************"
           "**************************************\n");
    printf("ID: %d | SRC: %s | DST: %s | TOS: 0x%x | TTL: %d\n", packet_id, packet_scrip,
           packet_dstip, packet_tos, packet_ttl);

    packeted_ptr += (4 * packet_hlen);
    int protocol_type = ip_hdr->ip_p;

    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmp *icmp_header;
    int src_port, dst_port;

    switch (protocol_type)
    {
    case IPPROTO_TCP:
        tcp_header = (struct tcphdr *)packeted_ptr;
        src_port = tcp_header->th_sport;
        dst_port = tcp_header->th_dport;
        printf("PROTO: TCP | FLAGS: %c/%c/%c | SPORT: %d | DPORT: %d |\n",
               (tcp_header->th_flags & TH_SYN ? 'S' : '-'),
               (tcp_header->th_flags & TH_ACK ? 'A' : '-'),
               (tcp_header->th_flags & TH_URG ? 'U' : '-'), src_port, dst_port);
        break;

    case IPPROTO_UDP:
        udp_header = (struct udphdr *)packeted_ptr;
        src_port = udp_header->uh_sport;
        dst_port = udp_header->uh_dport;
        printf("PROTO: UDP | SPORT: %d | DPORT: %d |\n", src_port, dst_port);
        break;
    case IPPROTO_ICMP:
        icmp_header = (struct icmp *)packeted_ptr;
        int icmp_type = icmp_header->icmp_type;
        int icmp_type_code = icmp_header->icmp_code;
        printf("PROTO: ICMP | TYPE: %d | CODE: %d |\n", icmp_type, icmp_type_code);
        break;
    }
}

int main(int argc, char const *argv[])
{
    const char *device = "eth0";
    char ERROR_BUFFER[PCAP_ERRBUF_SIZE];
    int packet_count = 5;

    pcap_t *capdev = pcap_open_live(device, BUFSIZ, 0, -1, ERROR_BUFFER);

    int link_hdr_type = pcap_datalink(capdev);
    switch (link_hdr_type)
    {
    case DLT_NULL:
        link_hdr_length = 4;
        break;
        // Ethernet
    case DLT_EN10MB:
        link_hdr_length = 14;
        break;
    default:
        link_hdr_length = 0;
    }

    if (capdev == NULL)
    {
        printf("ERROR: pcap_open_live() %s\n", ERROR_BUFFER);
        exit(1);
    }
    if (pcap_loop(capdev, packet_count, call_me, (u_char *)NULL) < 0)
    {
        printf("ERROR: pcap_loop() failed! %s\n", pcap_geterr(capdev));
        exit(1);
    }
    pcap_close(capdev);
    return 0;
}

// Outputs packet data correctly
