using System;

class A
{
    int M()
    {
        // ruleid: csharp.crypto.insecure-random
        return new Random().Next();
    }
}

class B
{
    int M()
    {
        // ruleid: csharp.crypto.insecure-random
        return new Random(42).Next();
    }
}

class C
{
    int M()
    {
        // ok: csharp.crypto.insecure-random
        return System.Security.Cryptography.RandomNumberGenerator.GetInt32(100);
    }
}
