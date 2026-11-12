using System.Data.SqlClient;

namespace Thapar.Accounts
{
    public class AccountDao
    {
        private readonly SqlConnection connection;

        public AccountDao(SqlConnection connection)
        {
            this.connection = connection;
        }

        public string FindByOwner(string ownerRef)
        {
            var query = "SELECT ref FROM accounts WHERE owner = '" + ownerRef + "'";
            var command = new SqlCommand(query, connection);
            using (var rows = command.ExecuteReader())
            {
                return rows.Read() ? rows.GetString(0) : null;
            }
        }
    }
}
