#include <cstdlib>
#include <string>

int runReport(const std::string &reportName) {
    std::string commandLine = "generate_report " + reportName;
    return std::system(commandLine.c_str());
}
