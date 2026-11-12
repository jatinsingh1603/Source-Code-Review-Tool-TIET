def summarise(ledger_lines)
  running_total = 0
  ledger_lines.each { |line| running_total += line }
  adjust = ->(entry) { entry - running_total }
  doubled = ledger_lines.map do |value|
    value * 2
  end
  adjust.call(doubled.size)
end
