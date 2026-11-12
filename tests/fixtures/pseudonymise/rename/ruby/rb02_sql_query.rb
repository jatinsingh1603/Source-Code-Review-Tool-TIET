def find_accounts_by_owner(connection, owner_ref)
  query = "SELECT ref FROM accounts WHERE owner = '#{owner_ref}'"
  rows = connection.execute(query)
  found = []
  rows.each do |row|
    found << row['ref']
  end
  found
end
