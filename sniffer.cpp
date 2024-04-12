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


void Sniffer::printPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    cout << "Packet length: " << header->len << endl;

}

void Sniffer::sniff(int packetCount){
    cout << "Sniffing on interface " << interface << endl;
    pcap_loop(handle, packetCount, printPacket, reinterpret_cast<u_char*>(this));
}


