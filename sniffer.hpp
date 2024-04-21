#ifndef snifferhpp
#define snifferhpp
#include <arpa/inet.h>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h> // pro ICMP hlavičky
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <pcap.h>
#include <iostream>
#include <string>
#include <vector>


using namespace std;

/**
 * @brief Configuration object with flags and values representing the cli arguments
 */
struct Config{

    string interface;
    bool tcp = false;
    bool udp = false;
    int port = 0;
    bool sourcePort = false;
    bool destinationPort = false;
    bool arp = false;
    bool ndp = false;
    bool icmp4 = false;
    bool icmp6 = false;
    bool igmp = false;
    bool mld = false;
    int packetCount = 1;
    bool allSpecified = false;
    bool onlySpecified = false;
    
    
};


class Sniffer {

    public:
        /**
         * @brief Construct a new Sniffer object
         * @param interface - interface to sniff
         */
        Sniffer( string interface);
        /**
         * @brief Destroy the Sniffer object
         */
        ~Sniffer();
        /**
         * @brief Method where sniffer starts sniffing packets
         */
        void sniff();

        /**
         * @brief Method for compiling setting the filter
         * @param filter - filter string
         */
        void setFilter(string& filter);

        /**
         * @brief Method for handling the ipv4 packet
         * @param packet - packet to handle
         */
        void handleIpv4Packet(const u_char *packet);
        /**
         * @brief Method for handling the ipv6 packet
         * @param packet - packet to handle
         */
        void handleIpv6Packet(const u_char *packet);

        /**
         * @brief Method for handling the arp packet
         * @param packet - packet to handle
         */
        void handleArpPacket(const u_char *packet);

        /**
         * @brief Method for handling the tcp packet
         * @param packet - packet to handle
         */
        void printTcpPacket(const u_char *packet);
        /**
         * @brief Method for handling the udp packet
         * @param packet - packet to handle
         */
        void printUdpPacket(const u_char *packet);
        /**
         * @brief Method for handling the icmp packet
         * @param packet - packet to handle
         */
        
        void printIcmp6Packet(const u_char *packet);
        

        /**
         * @brief Method where is recognized the type of packet and then it is handled by the appropriate method
         * @param args - arguments
         * @param header - packet header
         * @param packet - packet to handle
         */
        static void printPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
        int packetCount = 1;
        

    private:
    
        
        std::string interface;
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];
};

#endif