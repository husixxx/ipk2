#include "sniffer.cpp"
#include "helper.cpp"

/**
 * Ipk Project 2: Packet sniffer
 * Author: xhuska03@stud.fit.vutbr.cz
*/




int main(int argc, char *argv[]){
    
    signal(SIGINT, helper::signalHandler);
    // structure for storing configuration
    Config snifferConfig;
    // parse arguments and store config
    helper::parseArgs(argc, argv, snifferConfig);
    // if no interface specified print all active interfaces
    if(!snifferConfig.allSpecified){
        helper::PrintAllActiveInterfaces();
        return 0;
    }
    if(!snifferConfig.onlySpecified){
        cerr << "No interface specified" << endl;
        return 1;
    }
    
    // create sniffer object
    Sniffer sniffer(snifferConfig.interface);
    // set packet count
    sniffer.packetCount = snifferConfig.packetCount;
    // no args specified print all active interfaces
    // create filter from config
    string filter = helper::createFilter(snifferConfig);
    // set filter
    sniffer.setFilter(filter);
    // start sniffing
    sniffer.sniff();
    // cout << "filter" << filter << endl;

    return 0;
}