const fs = require("fs");
function read(req, res) {
  const data = fs.readFileSync("/var/data/" + req.query.file, "utf8");
  res.send(data);
}
