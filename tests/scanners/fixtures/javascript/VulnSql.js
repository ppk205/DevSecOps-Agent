const mysql = require("mysql2");
function byId(req, res) {
  const id = req.query.id;
  connection.query("SELECT * FROM users WHERE id = " + id, (e, rows) => res.send(rows));
}
function byName(req, res) {
  connection.query(`SELECT * FROM users WHERE name = '${req.query.name}'`, (e, rows) => res.send(rows));
}
