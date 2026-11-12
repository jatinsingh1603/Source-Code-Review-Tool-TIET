using System.Diagnostics;

class A
{
    void M(string host)
    {
        // ruleid: csharp.injection.process-start
        Process.Start("ping " + host);
    }
}

class B
{
    void M(string host)
    {
        // ruleid: csharp.injection.process-start
        Process.Start($"ping {host}");
    }
}

class C
{
    void M()
    {
        // ok: csharp.injection.process-start
        Process.Start("notepad.exe");
    }
}
