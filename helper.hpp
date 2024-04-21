#ifndef helpershpp
#define helpershpp
#include "sniffer.hpp"
#include <signal.h>

class helper{

    public:
    /**
     * @brief Create a filter string
     * @param sniffer_config - configuration object
     * @return string - filter string
    */
    static std::string createFilter(Config &sniffer_config );
    /**
     * @brief Method for parsing arguments, it manually checks if the arguments are correct and sets the configuration object with flags and values
     * @param argc - number of arguments
     * @param argv - arguments
     * @param sniffer_config - configuration object
    */
    static void parseArgs(int argc, char *argv[], Config &sniffer_config);
    /**
     * @brief Method for printing all active interfaces
    */
    static void PrintAllActiveInterfaces();
    /**
     * @brief Method for printing all active interfaces
    */
    static void signalHandler(int signum);
    
};
#endif