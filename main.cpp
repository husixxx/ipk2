#include "sniffer.cpp"
#include "helper.cpp"





int main(int argc, char *argv[]){
    
    // structure for storing configuration
    Config snifferConfig;
    // parse arguments and store config
    parseArgs(argc, argv, snifferConfig);
    
    // create sniffer object
    Sniffer sniffer(snifferConfig.interface);
    // set packet count
    sniffer.packetCount = snifferConfig.packetCount;
    // no args specified print all active interfaces
    if(!snifferConfig.allSpecified){
        PrintAllActiveInterfaces();
        return 0;
    }
    // create filter from config
    string filter = createFilter(snifferConfig);
    // set filter
    sniffer.setFilter(filter);
    // start sniffing
    sniffer.sniff();

    cout << filter << endl;


    return 0;
}