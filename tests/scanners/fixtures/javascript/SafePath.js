const fs = require("fs");
const path = require("path");
function read(req, res) {
  const data = fs.readFileSync(path.join("/var/data", path.basename(req.query.file)), "utf8");
  res.send(data);
}
