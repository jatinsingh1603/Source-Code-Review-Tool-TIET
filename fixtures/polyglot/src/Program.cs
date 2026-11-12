using System.Security.Cryptography;

class Program
{
    static void Main()
    {
        var h = MD5.Create();  // PG-VULN-005
    }
}
