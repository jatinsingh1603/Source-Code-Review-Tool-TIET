using System.Runtime.Serialization.Formatters.Binary;

class A
{
    object M(System.IO.Stream s)
    {
        // ruleid: csharp.deser.unsafe-formatter
        var f = new BinaryFormatter();
        return f.Deserialize(s);
    }
}

class C
{
    object M(System.IO.Stream s)
    {
        // ok: csharp.deser.unsafe-formatter
        return System.Text.Json.JsonSerializer.Deserialize<string>(s);
    }
}
