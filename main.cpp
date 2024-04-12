#include "sniffer.cpp"


string createFilter( Config& sniffer_config){
    vector<std::string> configs;

    if(sniffer_config.tcp){
        configs.push_back("tcp");
    }
    if(sniffer_config.udp){
        configs.push_back("udp");
    }
    if(sniffer_config.arp){
        configs.push_back("arp");
    }
    if(sniffer_config.icmp4){
        configs.push_back("icmp");
    }
    if(sniffer_config.icmp6){
        configs.push_back("icmp6");
    }
    if(sniffer_config.igmp){
        configs.push_back("igmp");
    }
    if(sniffer_config.mld){
        configs.push_back("mld");
    }

    if(sniffer_config.port > 0){
        if(sniffer_config.sourcePort){
            configs.push_back("src port " + to_string(sniffer_config.port));
        }else if(sniffer_config.destinationPort){
            configs.push_back("dst port " + to_string(sniffer_config.port));
        }else{
            configs.push_back("port " + to_string(sniffer_config.port));
        }
    }
    
    ostringstream final_filter;
    for(int i = 0; i < configs.size(); i++){
        if(i > 0){
            final_filter << " or ";
        }
        final_filter << configs[i];
    }

    return final_filter.str();

}

void PrintAllActiveInterfaces(){

    system("ip link show | grep 'state UP' -B1 | grep '<' | cut -d':' -f2 | tr -d ' '");

}



void parseArgs(int argc, char *argv[], Config &sniffer_config){
    int port = 0;
    for(int i = 1; i < argc; i++){
        if(string(argv[i]) == "-i" || string(argv[i]) == "--interface"){
            if( i + 1 >= argc){
                cout << "No interface specified" << endl;
                sniffer_config.interface = "";
            }else{
                sniffer_config.interface = string(argv[i+1]);
                i++;
                sniffer_config.allSpecified = true;
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
        }else if(string(argv[i]) == "--tcp" || string(argv[i]) == "-t"){
            sniffer_config.tcp = true;
            sniffer_config.allSpecified = true;
        }else if(string(argv[i]) == "--udp" || string(argv[i]) == "-u"){
            sniffer_config.udp = true;
            sniffer_config.allSpecified = true;
        }else if(string(argv[i]) == "--arp"){
            sniffer_config.arp = true;
            sniffer_config.allSpecified = true;
        }else if(string(argv[i]) == "--icmp4"){
            sniffer_config.icmp4 = true;
            sniffer_config.allSpecified = true;
        }else if(string(argv[i]) == "--icmp6"){
            sniffer_config.icmp6 = true;
            sniffer_config.allSpecified = true;
        }else if(string(argv[i]) == "--igmp"){
            sniffer_config.igmp = true;
            sniffer_config.allSpecified = true;
        }else if(string(argv[i]) == "--mld"){
            sniffer_config.mld = true;
            sniffer_config.allSpecified = true;
        }else if(string(argv[i]) == "-n"){
            if( i + 1 >= argc){
                cout << "-n not specified, only 1" << endl;
                sniffer_config.PacketCount = 1;
            }else{
                try{
                    sniffer_config.PacketCount = stoi(argv[i+1]);
                    i++;
                }catch(exception e){
                    cout << "Invalid -n specified" << endl;
                    exit(1);
                    
                }
                
            }

            sniffer_config.allSpecified = true;
        }else{
            cout << "Invalid argument: " << argv[i] << endl;
            exit(1);
        }
    }
}






int main(int argc, char *argv[]){
    
    
    Config sniffer_config;


    Sniffer sniffer("eth0");

    parseArgs(argc, argv, sniffer_config);
    
    if(!sniffer_config.allSpecified){
        PrintAllActiveInterfaces();
        return 0;
    }

    string filter = createFilter(sniffer_config);
    sniffer.setFilter(filter);
    sniffer.sniff(sniffer_config.PacketCount);

    

    //cout << filter << endl;


    return 0;
}