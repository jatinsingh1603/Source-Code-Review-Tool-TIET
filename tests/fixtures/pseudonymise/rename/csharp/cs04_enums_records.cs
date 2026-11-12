namespace Thapar.Core
{
    public enum RiskTier { LowRisk, HighRisk }

    public record StudentRecord(string RollNumber, double CgpaScore);

    public interface IAuditSink
    {
        void Record(string eventName);
    }
}
