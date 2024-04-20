#include "sniffer.cpp"
#include "helper.cpp"





int main(int argc, char *argv[]){
    
    signal(SIGINT, helper::signalHandler);
    // structure for storing configuration
    Config snifferConfig;
    // parse arguments and store config
    helper::parseArgs(argc, argv, snifferConfig);
    if(!snifferConfig.allSpecified){
        helper::PrintAllActiveInterfaces();
        return 0;
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
    cout << filter << endl;

    return 0;
}