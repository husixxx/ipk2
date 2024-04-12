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
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S%z", timeinfo);

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


    switch(ntohs(eth->ether_type)){
        case ETHERTYPE_IP:
            sniffer->handleIpv4Packet(packet); // Call handleIpv4Packet directly
            cout << "IP packet" << endl;
            break;
        case ETHERTYPE_ARP:
            cout << "ARP packet" << endl;
            break;       
        case ETHERTYPE_IPV6:
            cout << "IPv6 packet" << endl;
            break;
        default:
            cout << "Unknown packet" << endl;
            break;
    }

    cout << "Packet length: " << header->len << endl;

}

// Sniff function
void Sniffer::sniff(int packetCount){
    cout << "Sniffing on interface " << interface << endl;
    pcap_loop(handle, packetCount, printPacket, reinterpret_cast<u_char*>(this));
}

// Handle IPv6 packet
void Sniffer::handleIpv6Packet(const u_char *packet){
    const struct ip6_hdr *ip6header = (struct ip6_hdr *)packet;
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



    char srcIp[INET_ADDRSTRLEN]; // buffer for src
    char dstIp[INET_ADDRSTRLEN]; // buffer for dst
    inet_ntop(AF_INET, &(ipheader->ip_src), srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipheader->ip_dst), dstIp, INET_ADDRSTRLEN);

    int srcPort = ntohs(tcpheader->th_sport);
    int dstPort = ntohs(tcpheader->th_dport);

    std::cout << "src IP: " << srcIp << std::endl;
    std::cout << "dst IP: " << dstIp << std::endl;
    std::cout << "src port: " << srcPort << std::endl;
    std::cout << "dst port: " << dstPort << std::endl;

}


void Sniffer::printUdpPacket(const u_char *packet){
    cout << "UDP packet" << endl;
}

void Sniffer::printIcmpPacket(const u_char *packet){
    cout << "ICMP packet" << endl;
}
