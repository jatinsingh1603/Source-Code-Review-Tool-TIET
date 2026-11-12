<?php
function summarise($ledgerLines)
{
    $runningTotal = 0;
    foreach ($ledgerLines as $index => $line) {
        $runningTotal += $line;
    }
    $adjust = function ($entry) use ($runningTotal) {
        return $entry - $runningTotal;
    };
    $doubled = array_map(fn($value) => $value * 2, $ledgerLines);
    return $adjust(count($doubled));
}
