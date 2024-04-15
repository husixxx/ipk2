#include "sniffer.hpp"

std::string createFilter(Config &sniffer_config );
void parseArgs(int argc, char *argv[], Config &sniffer_config);
void PrintAllActiveInterfaces();