#include "sniffer.hpp"

Sniffer::Sniffer( string interface) : interface(interface) , handle(nullptr) {

    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

    if(handle == nullptr){
        cerr << "Could not open device " << interface << ": " << errbuf << endl;
        exit(1);
    }

    
}


Sniffer::~Sniffer(){
    pcap_close(handle);
}

void printPacketData(const u_char* packet, int length) {
    std::cout << std::hex << std::setfill('0'); // Nastavíme formátování pro hexadecimální výstup
    for (int i = 0; i < length; ++i) {
        // Začátek nového řádku
        if (i % 16 == 0) {
            if (i != 0) {
                std::cout << " "; // Mezera mezi hex a ASCII reprezentací na konci řádku
                // Výpis ASCII reprezentace pro předchozí řádek
                for (int j = i - 16; j < i; ++j)
                    std::cout << (isprint(packet[j]) ? static_cast<char>(packet[j]) : '.');
                std::cout << std::endl;
            }
            // Adresa řádku
            std::cout << "0x" << std::setw(4) << i << ": ";
        }

        // Výpis hexadecimálního znaku
        std::cout << std::setw(2) << static_cast<unsigned>(packet[i]) << " ";
    }

    // Doplňující mezery pro poslední řádek, pokud není úplný
    int bytes_left = length % 16;
    if (bytes_left > 0) {
        for (int i = 0; i < 16 - bytes_left; ++i) {
            std::cout << "   "; // Tři mezery pro každý neexistující byte
        }
    }

    // Poslední řádek ASCII výpisu
    std::cout << " "; // Mezera mezi hex a ASCII reprezentací
    int start = length - (length % 16);
    for (int i = start; i < length; ++i)
        std::cout << (isprint(packet[i]) ? static_cast<char>(packet[i]) : '.');
    std::cout << std::endl;

    std::cout << std::dec; // Vrátíme se k decimálnímu formátování
}



void Sniffer::setFilter(string& filter){

    struct bpf_program fp;
    if(pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1){
        cerr << "Could not parse filter " << filter << ": " << pcap_geterr(handle) << endl;
        exit(1);
    }
    

    if(pcap_setfilter(handle, &fp) == -1){
        cerr << "Could not install filter " << filter << ": " << pcap_geterr(handle) << endl;
        exit(1);
    }

    pcap_freecode(&fp); // free 
}


void Sniffer::handleIpv4Packet(const u_char *packet){
    struct ip *ipheader = (struct ip *)(packet + sizeof(struct ether_header));


    std::cout << "src IP: " << inet_ntoa(ipheader->ip_src)<< std::endl;
    std::cout << "dst IP: " << inet_ntoa(ipheader->ip_dst) << std::endl;
    
    switch(ipheader->ip_p){
        case IPPROTO_TCP:
            printTcpPacket(packet + ipheader->ip_hl * 4);
            break;
        case IPPROTO_UDP:
            printUdpPacket(packet + ipheader->ip_hl * 4);
            break;
        case IPPROTO_ICMP:
            printIcmpPacket(packet + ipheader->ip_hl * 4);
            break;
        default:
            cout << "Unknown transport protocol" << endl;
            break;
    }
}

void Sniffer::printPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    Sniffer* sniffer = reinterpret_cast<Sniffer*>(args);

    
    time_t timer = header->ts.tv_sec;
    struct tm *timeinfo = localtime(&timer);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", timeinfo);
    char tzbuffer[6];
    strftime(tzbuffer, sizeof(tzbuffer), "%z", timeinfo);

    // Vložení dvojtečky do časového pásma
    std::string tzformatted = std::string(tzbuffer).insert(3, ":");

    // Vytvoření konečného řetězce
    std::string timestamp = std::string(buffer) + tzformatted;
    cout << "timestamp: " << timestamp << endl;
    struct ether_header *eth = (struct ether_header *) packet;

    char srcMac[18], dstMac[18];
    snprintf(srcMac, sizeof(srcMac), "%02x:%02x:%02x:%02x:%02x:%02x",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    snprintf(dstMac, sizeof(dstMac), "%02x:%02x:%02x:%02x:%02x:%02x",
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    std::cout << "src MAC: " << srcMac << std::endl;
    std::cout << "dst MAC: " << dstMac << std::endl;
    cout << "frame length: " << header->len << endl;


    switch(ntohs(eth->ether_type)){
        case ETHERTYPE_IP:
            sniffer->handleIpv4Packet(packet); // Call handleIpv4Packet directly
            //cout << "IP packet" << endl;
            break;
        case ETHERTYPE_ARP:
            cout << "ARP packet" << endl;
            break;       
        case ETHERTYPE_IPV6:
            sniffer->handleIpv6Packet(packet);
            //cout << "IPv6 packet" << endl;
            break;
        default:
            cout << "Unknown packet" << endl;
            break;
    }

    printPacketData(packet, header->len);

}

// Sniff function
void Sniffer::sniff(){
   // cout << "Sniffing on interface " << interface << endl;
    pcap_loop(handle, packetCount, printPacket, reinterpret_cast<u_char*>(this));
}

// Handle IPv6 packet
void Sniffer::handleIpv6Packet(const u_char *packet){

    char ip6_addr[INET6_ADDRSTRLEN];
    const struct ip6_hdr *ip6header = (struct ip6_hdr *)packet;

    std::cout << "src IP: " << inet_ntop(AF_INET6, &(ip6header->ip6_src), ip6_addr, INET6_ADDRSTRLEN ) << std::endl;
    std::cout << "dst IP: " << inet_ntop(AF_INET6, &(ip6header->ip6_dst), ip6_addr, INET6_ADDRSTRLEN ) << std::endl;
    switch(ip6header->ip6_nxt){
        case IPPROTO_TCP:
            printTcpPacket(packet + sizeof(struct ip6_hdr));
            break;
        case IPPROTO_UDP:
            printUdpPacket(packet + sizeof(struct ip6_hdr));
            break;
        case IPPROTO_ICMPV6:
            printIcmpPacket(packet + sizeof(struct ip6_hdr));
            break;
        default:
            cout << "Unknown transport protocol" << endl;
            break;
    }
}

void Sniffer::handleArpPacket(const u_char *packet){
    cout << "ARP packet" << endl;
}



/**
 * Print TCP packet
 * @param packet
 * 
*/
void Sniffer::printTcpPacket(const u_char *packet){

    const struct ip *ipheader = (const struct ip *)packet;
    const struct tcphdr *tcpheader = (struct tcphdr *)packet;

    // char srcIp[INET_ADDRSTRLEN]; // buffer for src
    // char dstIp[INET_ADDRSTRLEN]; // buffer for dst
    // inet_ntop(AF_INET, &(ipheader->ip_src), srcIp, INET_ADDRSTRLEN);
    // inet_ntop(AF_INET, &(ipheader->ip_dst), dstIp, INET_ADDRSTRLEN);

    int srcPort = ntohs(tcpheader->th_sport);
    int dstPort = ntohs(tcpheader->th_dport);

    // std::cout << "src IP: " << srcIp << std::endl;
    // std::cout << "dst IP: " << dstIp << std::endl;

    std::cout << "src port: " << srcPort << std::endl;
    std::cout << "dst port: " << dstPort << std::endl;

}


void Sniffer::printUdpPacket(const u_char *packet){
    const struct ip *ipheader = (const struct ip *)packet;
    const struct udphdr *udpheader = (struct udphdr *)(packet + sizeof(ether_header) + ipheader->ip_hl * 4);

    // char srcIp[INET_ADDRSTRLEN];
    // char dstIp[INET_ADDRSTRLEN];
    // inet_ntop(AF_INET, &(ipheader->ip_src), srcIp, INET_ADDRSTRLEN);
    // inet_ntop(AF_INET, &(ipheader->ip_dst), dstIp, INET_ADDRSTRLEN);

    int srcPort = ntohs(udpheader->source);
    int dstPort = ntohs(udpheader->dest);

  //  std::cout << "UDP Packet:" << std::endl;
    // std::cout << "src IP: " << srcIp << std::endl;
    // std::cout << "dst IP: " << dstIp << std::endl;
    std::cout << "src port: " << srcPort << std::endl;
    std::cout << "dst port: " << dstPort << std::endl;
}

void Sniffer::printIcmpPacket(const u_char *packet){
    const struct ip *ipheader = (const struct ip *)packet;
    const struct icmp *icmpheader = (const struct icmp *)(packet + ipheader->ip_hl * 4);

    // char srcIp[INET_ADDRSTRLEN];
    // char dstIp[INET_ADDRSTRLEN];
    // inet_ntop(AF_INET, &(ipheader->ip_src), srcIp, INET_ADDRSTRLEN);
    // inet_ntop(AF_INET, &(ipheader->ip_dst), dstIp, INET_ADDRSTRLEN);

    
    // std::cout << "src IP: " << srcIp << std::endl;
    // std::cout << "dst IP: " << dstIp << std::endl;
    // std::cout << "Type: " << (int) icmpheader->icmp_type << std::endl;
    // std::cout << "Code: " << (int) icmpheader->icmp_code << std::endl;
}
