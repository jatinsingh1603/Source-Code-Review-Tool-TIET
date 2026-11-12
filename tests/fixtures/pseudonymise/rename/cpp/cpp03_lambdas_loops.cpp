#include <vector>

int summarise(const std::vector<int> &ledgerLines) {
    int runningTotal = 0;
    for (int line : ledgerLines) {
        runningTotal += line;
    }
    auto adjust = [&runningTotal](int entry) { return entry - runningTotal; };
    return adjust(static_cast<int>(ledgerLines.size()));
}
