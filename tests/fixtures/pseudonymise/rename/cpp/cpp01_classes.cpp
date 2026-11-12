#include <string>

namespace payroll {

class FestivalBonusCalculator {
public:
    explicit FestivalBonusCalculator(long baseRate) : baseRate_(baseRate), accrued_(0) {}

    long accrue(int employeeCount) {
        long gross = baseRate_ * employeeCount;
        accrued_ += gross;
        return accrued_;
    }

    std::string describe(const std::string &schemeName) const {
        return "scheme " + schemeName;
    }

private:
    long baseRate_;
    long accrued_;
};

}  // namespace payroll
