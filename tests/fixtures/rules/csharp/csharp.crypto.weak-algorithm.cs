using System.Security.Cryptography;

class A
{
    object M()
    {
        // ruleid: csharp.crypto.weak-algorithm
        return MD5.Create();
    }
}

class C
{
    object M()
    {
        // ok: csharp.crypto.weak-algorithm
        return SHA256.Create();
    }
}
