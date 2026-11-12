<?php
trait AuditTrail
{
    protected $auditEntries = [];

    public function recordEvent($eventName)
    {
        $this->auditEntries[] = $eventName;
    }
}

enum RiskTier: int
{
    case LowRisk = 1;
    case HighRisk = 5;
}

interface SessionStore
{
    public function fetchSession($sessionToken);
}
