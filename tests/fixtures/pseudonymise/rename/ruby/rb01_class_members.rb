module Payroll
  class FestivalBonusCalculator
    SCHEME_CAP = 100
    attr_reader :accrued

    def initialize(base_rate)
      @base_rate = base_rate
      @accrued = 0
    end

    def accrue(employee_count)
      gross = @base_rate * employee_count
      @accrued += gross
      @accrued
    end
  end
end
