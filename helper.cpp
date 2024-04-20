
#include "helper.hpp"

std::string helper::createFilter( Config &sniffer_config ){
    std::string filter = "";
    if(sniffer_config.onlySpecified){
        return filter;
    }
    filter = "len < 0 ";
    if(sniffer_config.tcp){
        filter += "or tcp ";
        if(sniffer_config.port > 0){
            if(sniffer_config.sourcePort){
                filter += "src port " + to_string(sniffer_config.port) + " ";
            }else if(sniffer_config.destinationPort){
                filter += "dst port " + to_string(sniffer_config.port)  + " " ;
            }else{
                filter += "port " + to_string(sniffer_config.port)  + " ";
            }
        }
    }
    if(sniffer_config.udp){
        filter += "or udp ";
        if(sniffer_config.port > 0){
            if(sniffer_config.sourcePort){
                filter += "src port " + to_string(sniffer_config.port) + " ";
            }else if(sniffer_config.destinationPort){
                filter += "dst port " + to_string(sniffer_config.port)  + " " ;
            }else{
                filter += "port " + to_string(sniffer_config.port)  + " ";
            }
        }
    }
    if(!sniffer_config.udp && !sniffer_config.tcp && sniffer_config.port > 0){
        filter += "or tcp ";
        if(sniffer_config.sourcePort){
            filter += "src port " + to_string(sniffer_config.port) + " ";
        }else if(sniffer_config.destinationPort){
            filter += "dst port " + to_string(sniffer_config.port)  + " " ;
        }else{
            filter += "port " + to_string(sniffer_config.port)  + " ";
        }
        filter += "or udp ";
        if(sniffer_config.sourcePort){
            filter += "src port " + to_string(sniffer_config.port) + " ";
        }else if(sniffer_config.destinationPort){
            filter += "dst port " + to_string(sniffer_config.port)  + " " ;
        }else{
            filter += "port " + to_string(sniffer_config.port)  + " ";
        }
        
    }
    if(sniffer_config.arp){
        filter += "or arp ";
    }
    if(sniffer_config.ndp){
        filter += "or icmp6 and ip6[40] >= 133 and ip6[40] <= 137";
    }
    
    if(sniffer_config.icmp4){
        filter += "or icmp ";
    }
    if(sniffer_config.icmp6){
        filter += "or icmp6 ";
    }
    if(sniffer_config.igmp){
        filter += "or igmp ";
    }
    if(sniffer_config.mld){
        filter += "or icmp6 and (ip6[40] >= 130 and ip6[40] <= 132 or ip6[40] = 143)";
    }
    
    return filter;
}

void helper::PrintAllActiveInterfaces(){

    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldevs, errbuf) == -1){
        cout << "Error finding devices: " << errbuf << endl;
        exit(1);
    }
    while(alldevs != NULL){
        cout << alldevs->name << endl;
        alldevs = alldevs->next;
    }

    pcap_freealldevs(alldevs);

}



void helper::parseArgs(int argc, char *argv[], Config &sniffer_config){
    int port = 0;
    for(int i = 1; i < argc; i++){
        if(string(argv[i]) == "-i" || string(argv[i]) == "--interface"){
            if( i + 1 >= argc){
                sniffer_config.interface = "";
            }else{
                sniffer_config.interface = string(argv[i+1]);
                i++;
                sniffer_config.allSpecified = true;
                sniffer_config.onlySpecified = true;
            }

        }else if(string(argv[i]) == "-p" || string(argv[i]) == "--port-source" || string(argv[i]) == "--port-destination"){

            if(string(argv[i]) == "--port-source"){
                sniffer_config.sourcePort = true;
            }else if(string(argv[i]) == "--port-destination"){
                sniffer_config.destinationPort = true;
            }

            if( i + 1 >= argc){
                cout << "No port specified" << endl;
                sniffer_config.port = 0;
            }else{
                try{
                    sniffer_config.port = stoi(argv[i+1]);
                    i++;
                }catch(exception e){
                    cout << "Invalid port specified" << endl;
                    exit(1);
                    
                }
                
            }
            sniffer_config.allSpecified = true;
            sniffer_config.onlySpecified = false;
        }else if(string(argv[i]) == "--tcp" || string(argv[i]) == "-t"){
            sniffer_config.tcp = true;
            sniffer_config.allSpecified = true;
            sniffer_config.onlySpecified = false;
        }else if(string(argv[i]) == "--udp" || string(argv[i]) == "-u"){
            sniffer_config.udp = true;
            sniffer_config.allSpecified = true;
            sniffer_config.onlySpecified = false;
        }else if(string(argv[i]) == "--arp"){
            sniffer_config.arp = true;
            sniffer_config.allSpecified = true;
            sniffer_config.onlySpecified = false;
        }else if(string(argv[i]) == "--icmp4"){
            sniffer_config.icmp4 = true;
            sniffer_config.allSpecified = true;
            sniffer_config.onlySpecified = false;
        }else if(string(argv[i]) == "--icmp6"){
            sniffer_config.icmp6 = true;
            sniffer_config.allSpecified = true;
            sniffer_config.onlySpecified = false;
        }else if(string(argv[i]) == "--igmp"){
            sniffer_config.igmp = true;
            sniffer_config.allSpecified = true;
            sniffer_config.onlySpecified = false;
        }else if(string(argv[i]) == "--mld"){
            sniffer_config.mld = true;
            sniffer_config.allSpecified = true;
            sniffer_config.onlySpecified = false;
        }else if(string(argv[i]) == "-n"){
            if( i + 1 >= argc){
                cout << "-n not specified, only 1" << endl;
                sniffer_config.packetCount = 1;
            }else{
                try{
                    sniffer_config.packetCount = stoi(argv[i+1]);
                    i++;
                }catch(exception e){
                    cout << "Invalid -n specified" << endl;
                    exit(1);
                    
                }
                
            }

            sniffer_config.allSpecified = true;
            sniffer_config.onlySpecified = false;
        }else if(string(argv[i]) == "--ndp"){
            sniffer_config.ndp = true;
            sniffer_config.allSpecified = true;
            sniffer_config.onlySpecified = false;
        }
        else{
            cout << "Invalid argument: " << argv[i] << endl;
            exit(1);
        }
    }
}

void helper::signalHandler(int signum){
    cout << "SIGINT received, closing...";
    exit(signum);
}
