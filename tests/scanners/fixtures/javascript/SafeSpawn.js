const { spawn } = require("child_process");

function convert(req, res) {
  const child = spawn("/usr/bin/convert", [req.query.file]);
  child.stdout.on("data", (chunk) => res.write(chunk));
}
module.exports = { convert };
