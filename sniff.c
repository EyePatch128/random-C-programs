#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/time.h>

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


// Handle packet callback
void onPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet){

        const struct sniff_ethernet *ethernet;                          // Ethernet Header
        const struct sniff_ip *ip;                                      // IP Header
        const struct sniff_tcp *tcp;                                    // TCP header
        const char *payload;                                            // Packet payload

        u_int size_ip;
        u_int size_tcp;

        printf("Packet Received:\n");

        ethernet = (struct sniff_ethernet *)(packet);
        ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;
        if(size_ip < 20){
                printf("Invalid IP header length: %u bytes\n", size_ip);
                return;
        };
        tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp) * 4;
        if(size_tcp < 20){
                printf("Invalid TCP header length: %u bytes\n", size_tcp);
                return;
        };
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        char *ip_src, ip_dst;
        printf("%s", payload);
        //printf("Length: %u", pkthdr->caplen);
        //printf("Length: %u\r\r%s  \n", pkthdr->caplen, ip->ip_p);
        //printf("%d", (ip->ip_src).s_addr);
};


int main(int argc, char **argv){
        char *dev, err_buf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;
        pcap_if_t *alldevs;

        // Look up network device

        if(pcap_findalldevs(&alldevs, err_buf) == -1){
                fprintf(stderr, "Unable to find network device: %s\n", err_buf);
                exit(EXIT_FAILURE);
        };
        dev = (char *) (alldevs->name);

        printf("Listening on %s\n", dev);

        // Open device for sniffing
        handle = pcap_open_live(dev, 65535, 0, 1000, err_buf);
        if(handle == NULL){
                fprintf(stderr, "Unable to open device %s: %s\n", dev, err_buf);
                exit(EXIT_FAILURE);
        };

        // Check for link-layer header compatibiliy
        if(pcap_datalink(handle) != DLT_EN10MB){
                fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
                exit(EXIT_FAILURE);
        };


        // Capture packets
        printf("Starting packet sniffing\n");
        if((pcap_loop(handle, -1, onPacket, NULL)) == -1){
                fprintf(stderr, "Unable to capture packets on %s: %s\n", dev, err_buf);
                exit(EXIT_FAILURE);
        }

        // Closing sniffing
        pcap_close(handle);
        return 0;

};
