<?php
namespace Thapar\Payroll;

class FestivalBonusCalculator
{
    private $baseRate;
    private $accrued = 0;
    const SCHEME_CAP = 100;

    public function __construct($baseRate)
    {
        $this->baseRate = $baseRate;
    }

    public function accrue($employeeCount)
    {
        $gross = $this->baseRate * $employeeCount;
        $this->accrued += $gross;
        return $this->accrued;
    }
}
