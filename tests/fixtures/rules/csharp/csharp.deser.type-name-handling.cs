class A
{
    void M(dynamic settings)
    {
        // ruleid: csharp.deser.type-name-handling
        settings.TypeNameHandling = TypeNameHandling.Auto;
    }
}

class B
{
    void M(dynamic settings)
    {
        // ok: csharp.deser.type-name-handling
        settings.TypeNameHandling = TypeNameHandling.None;
    }
}
