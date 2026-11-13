Stopping `codekavach serve` now gives running scans up to 10 seconds to stop at their next checkpoint before the database is closed, so a scan no longer opens a database connection after shutdown.
