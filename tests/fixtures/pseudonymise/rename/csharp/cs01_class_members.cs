namespace Thapar.Payroll
{
    public class FestivalBonusCalculator
    {
        private readonly long _baseRate;
        private long accrued;

        public FestivalBonusCalculator(long baseRate)
        {
            _baseRate = baseRate;
        }

        public long Accrue(int employeeCount)
        {
            var gross = _baseRate * employeeCount;
            accrued += gross;
            return accrued;
        }
    }
}
