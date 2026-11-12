using System.Net.Http;

class A
{
    object M(HttpClient client, string target)
    {
        // ruleid: csharp.ssrf.request-derived-url
        return client.GetStringAsync(target);
    }
}

class B
{
    object M(HttpClient client, HttpRequest req)
    {
        // ruleid: csharp.ssrf.request-derived-url
        return client.GetAsync(req.Query["u"]);
    }
}

class C
{
    object M(HttpClient client)
    {
        // ok: csharp.ssrf.request-derived-url
        return client.GetStringAsync("https://api.example.test/v1");
    }
}
