using System.IO;

class A
{
    string M(string name)
    {
        // ruleid: csharp.path.file-access
        return File.ReadAllText("/srv/files/" + name);
    }
}

class B
{
    string M(HttpRequest req)
    {
        // ruleid: csharp.path.file-access
        return File.ReadAllText(req.Query["f"]);
    }
}

class C
{
    string M()
    {
        // ok: csharp.path.file-access
        return File.ReadAllText("/srv/files/readme.txt");
    }
}
