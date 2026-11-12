using System.Security.Cryptography;

class A
{
    void M(Aes aes)
    {
        // ruleid: csharp.crypto.ecb-mode
        aes.Mode = CipherMode.ECB;
    }
}

class B
{
    void M(Aes aes)
    {
        // ok: csharp.crypto.ecb-mode
        aes.Mode = CipherMode.CBC;
    }
}
