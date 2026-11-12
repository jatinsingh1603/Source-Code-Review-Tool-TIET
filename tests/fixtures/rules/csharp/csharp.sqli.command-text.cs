using System.Data.SqlClient;

class A
{
    object M(SqlConnection conn, string id)
    {
        // ruleid: csharp.sqli.command-text
        return new SqlCommand("SELECT * FROM t WHERE id = " + id, conn);
    }
}

class B
{
    object M(SqlConnection conn, string id)
    {
        // ruleid: csharp.sqli.command-text
        return new SqlCommand($"SELECT * FROM t WHERE id = {id}", conn);
    }
}

class C
{
    object M(SqlConnection conn)
    {
        // ok: csharp.sqli.command-text
        return new SqlCommand("SELECT * FROM t WHERE id = @id", conn);
    }
}
