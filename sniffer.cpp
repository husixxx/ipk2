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
    cout << endl;
    cout << hex << setfill('0'); // set formating for hex output
    for (int i = 0; i < length; ++i) {
        
        if (i % 16 == 0) {
            if (i != 0) {
                cout << " "; // space between hex and ASCII representation
                // print ascii
                for (int j = i - 16; j < i; ++j)
                    cout << (isprint(packet[j]) ? static_cast<char>(packet[j]) : '.');
                cout << endl;
            }
            // adrress 
            cout << "0x" << setw(4) << i << ": ";
        }

        // hexa print
        cout << setw(2) << static_cast<unsigned>(packet[i]) << " ";
    }

    // padding for last line
    int bytes_left = length % 16;
    if (bytes_left > 0) {
        for (int i = 0; i < 16 - bytes_left; ++i) {
            cout << "   "; // padding
        }
    }

    // last lane
    cout << " ";
    int start = length - (length % 16);
    for (int i = start; i < length; ++i)
        cout << (isprint(packet[i]) ? static_cast<char>(packet[i]) : '.');
    cout << endl;

    cout << dec; // dec print
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

    cout << "-- IPv4" << endl;
    cout << "src IP: " << inet_ntoa(ipheader->ip_src)<< endl;
    cout << "dst IP: " << inet_ntoa(ipheader->ip_dst) << endl;
    
    switch(ipheader->ip_p){
        case IPPROTO_TCP:
            printTcpPacket(packet + ipheader->ip_hl * 4);
            break;
        case IPPROTO_UDP:
            printUdpPacket(packet + ipheader->ip_hl * 4);
            break;
        case IPPROTO_ICMP:
            printIcmp6Packet(packet + ipheader->ip_hl * 4);
            break;
        default:
            cout << "Unknown transport protocol" << endl;
            break;
    }
}

void Sniffer::printPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    // get sniffer object from args
    Sniffer* sniffer = reinterpret_cast<Sniffer*>(args);

    // get timestamp
    time_t timer = header->ts.tv_sec;
    struct tm *timeinfo = localtime(&timer);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", timeinfo);
    char tzbuffer[6];
    strftime(tzbuffer, sizeof(tzbuffer), "%z", timeinfo);

    // format timezone            
    string tzformatted = string(tzbuffer).insert(3, ":");
    string timestamp = string(buffer) + tzformatted;
    struct ether_header *eth = (struct ether_header *) packet;

    // print timestamp of the packet
    cout << "timestamp: " << timestamp << endl;
    // ethernet layer
    cout <<"-- Ethernet" << endl;

    // get the mac addresses
    char srcMac[18], dstMac[18];
    snprintf(srcMac, sizeof(srcMac), "%02x:%02x:%02x:%02x:%02x:%02x",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    snprintf(dstMac, sizeof(dstMac), "%02x:%02x:%02x:%02x:%02x:%02x",
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    cout << "src MAC: " << srcMac << endl;
    cout << "dst MAC: " << dstMac << endl;
    cout << "frame length: " << header->len << endl;


    switch(ntohs(eth->ether_type)){
        case ETHERTYPE_IP:
            sniffer->handleIpv4Packet(packet); // Call handleIpv4Packet directly
            break;
        case ETHERTYPE_ARP:
            sniffer->handleArpPacket(packet);
            break;       
        case ETHERTYPE_IPV6:
            sniffer->handleIpv6Packet(packet);
            break;
        default:
            cout << "Unknown packet" << endl;
            break;
    }

    // finally print hex dump
    printPacketData(packet, header->len);

}

// Sniff function
void Sniffer::sniff(){
    //cout << "Sniffing on interface " << interface << endl;
    pcap_loop(handle, packetCount, printPacket, reinterpret_cast<u_char*>(this));
}

// Handle IPv6 packet
void Sniffer::handleIpv6Packet(const u_char *packet){

    // get the header
    char ip6_addr[INET6_ADDRSTRLEN];
    const struct ip6_hdr *ip6header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    
    cout << "-- IPv6" << endl;

    cout << "src IP: " << inet_ntop(AF_INET6, &(ip6header->ip6_src), ip6_addr, INET6_ADDRSTRLEN ) << endl;
    cout << "dst IP: " << inet_ntop(AF_INET6, &(ip6header->ip6_dst), ip6_addr, INET6_ADDRSTRLEN ) << endl;

    // switch for transport protocol
    switch(ip6header->ip6_nxt){
        case IPPROTO_TCP:
            printTcpPacket(packet + sizeof(struct ip6_hdr));
            break;
        case IPPROTO_UDP:
            printUdpPacket(packet + sizeof(struct ip6_hdr));
            break;
        case IPPROTO_ICMPV6:
            printIcmp6Packet(packet);
            break;
        default:
            cerr << "Unknown transport protocol ipv6" << to_string(ip6header->ip6_nxt) << endl;
            break;
    }
}

void Sniffer::handleArpPacket(const u_char *packet){
    auto arpheader = (struct ether_arp *)(packet + sizeof(struct ether_header));
    cout << "-- Arp" << endl;
    cout << "operation: " << ntohs(arpheader->arp_op) << endl; // 1 is request, 2 is reply
    // print this sha but as mac adress
    cout << "sha MAC: " << ether_ntoa((struct ether_addr *)arpheader->arp_sha) << endl;
    cout << "tha MAC: " << ether_ntoa((struct ether_addr *)arpheader->arp_tha) << endl;
    cout << "spa IP: " << inet_ntoa(*(struct in_addr *)arpheader->arp_spa) << endl;
    cout << "tpa IP: " << inet_ntoa(*(struct in_addr *)arpheader->arp_tpa) << endl;
}




/**
 * Print TCP packet
 * @param packet
 * 
*/
void Sniffer::printTcpPacket(const u_char *packet){

    const struct ip *ipheader = (const struct ip *)packet;
    const struct tcphdr *tcpheader = (struct tcphdr *)(packet + sizeof(ether_header) + ipheader->ip_hl * 4);
    cout << "-- TCP" << endl;
    int srcPort = ntohs(tcpheader->source);
    int dstPort = ntohs(tcpheader->dest);

    cout << "src port: " << srcPort << endl;
    cout << "dst port: " << dstPort << endl;

}


void Sniffer::printUdpPacket(const u_char *packet){
    const struct ip *ipheader = (const struct ip *)packet;
    const struct udphdr *udpheader = (struct udphdr *)(packet + sizeof(ether_header) + ipheader->ip_hl * 4);

    int srcPort = ntohs(udpheader->source);
    int dstPort = ntohs(udpheader->dest);

    cout << "-- UDP" << endl;
    cout << "src port: " << srcPort << endl;
    cout << "dst port: " << dstPort << endl;
}

void Sniffer::printIcmp6Packet(const u_char *packet){
    
    // icmp header pointer
    auto icmpheader = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(ip6_hdr));

    cout << "-- ICMP" << endl;
    cout << "type:        " << unsigned(icmpheader->type) << endl;
    cout << "code:        " << unsigned(icmpheader->code) << endl;
}
