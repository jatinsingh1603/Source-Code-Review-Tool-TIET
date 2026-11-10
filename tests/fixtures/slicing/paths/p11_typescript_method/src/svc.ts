export class Users {
  constructor(private db: Db) {}

  find(req: Request): Promise<Row[]> {
    const name: string = req.params.name;
    const clean = name.trim();
    return this.db.query("SELECT * FROM users WHERE name = '" + clean + "'");
  }
}
