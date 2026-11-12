def a(id)
  # ruleid: ruby.sqli.query-interpolation
  User.where("id = #{id}")
end

def b(name)
  # ruleid: ruby.sqli.query-interpolation
  User.find_by_sql("SELECT * FROM users WHERE name = '" + name + "'")
end

def c(id)
  # ok: ruby.sqli.query-interpolation
  User.where("id = ?", id)
end

def d(id)
  # ok: ruby.sqli.query-interpolation
  User.where(id: id)
end
