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
#include <pcap.h>
#include <iostream>
#include <string>
#include <vector>


using namespace std;

struct Config{
    string interface;
    bool tcp = false;
    bool udp = false;
    int port = 0;
    bool sourcePort = false;
    bool destinationPort = false;
    bool arp = false;
    bool icmp4 = false;
    bool icmp6 = false;
    bool igmp = false;
    bool mld = false;
    int PacketCount = 1;
    bool allSpecified = false;
    
    
};


class Sniffer {

    public:
        // constructor
        Sniffer( string interface);
        ~Sniffer();
        void sniff(int packetCount);

        void setFilter(string& filter);

        void handleIpv4Packet(const u_char *packet);
        void handleIpv6Packet(const u_char *packet);
        void handleArpPacket(const u_char *packet);
        void printTcpPacket(const u_char *packet);
        void printUdpPacket(const u_char *packet);
        void printIcmpPacket(const u_char *packet);
        static void printPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
        

    private:
        std::string interface;
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];
};

#endif