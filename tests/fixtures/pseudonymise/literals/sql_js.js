const q1 = "UPDATE loyalty_points SET tier = 'gold' WHERE member_uuid = ?";
const q2 = "SELECT invoice_total FROM ledger_entries WHERE port_number = 5432";
const q3 = "INSERT INTO audit_events (actor_name, event_time) VALUES (?, ?)";
