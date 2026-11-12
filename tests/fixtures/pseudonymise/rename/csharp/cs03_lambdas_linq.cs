using System.Collections.Generic;
using System.Linq;

namespace Thapar.Reports
{
    public static class Summary
    {
        public static int Summarise(List<int> ledgerLines)
        {
            var runningTotal = 0;
            foreach (var line in ledgerLines)
            {
                runningTotal += line;
            }
            var doubled = ledgerLines.Select(value => value * 2).ToList();
            return runningTotal + doubled.Count;
        }
    }
}
