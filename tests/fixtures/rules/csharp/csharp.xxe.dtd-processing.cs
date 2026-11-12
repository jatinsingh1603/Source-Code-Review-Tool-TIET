using System.Xml;

class A
{
    XmlReaderSettings M()
    {
        // ruleid: csharp.xxe.dtd-processing
        return new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
    }
}

class B
{
    void M(XmlDocument d)
    {
        // ruleid: csharp.xxe.dtd-processing
        d.XmlResolver = new XmlUrlResolver();
    }
}

class C
{
    XmlReaderSettings M()
    {
        // ok: csharp.xxe.dtd-processing
        return new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
    }
}
