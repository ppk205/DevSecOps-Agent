const mysql = require("mysql2");
function byId(req, res) {
  connection.query("SELECT * FROM users WHERE id = ?", [req.query.id], (e, rows) => res.send(rows));
}
function all(req, res) {
  connection.query(`SELECT id, name FROM users`, (e, rows) => res.send(rows));
}
