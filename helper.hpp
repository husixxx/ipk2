#ifndef helpershpp
#define helpershpp
#include "sniffer.hpp"

class helper{

    public:
    static std::string createFilter(Config &sniffer_config );
    static void parseArgs(int argc, char *argv[], Config &sniffer_config);
    static void PrintAllActiveInterfaces();

};
#endif