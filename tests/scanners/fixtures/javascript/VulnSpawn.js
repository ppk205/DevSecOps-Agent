const { spawn } = require("child_process");

function convert(req, res) {
  const child = spawn(req.query.tool, ["--help"], { shell: true });
  child.stdout.on("data", (chunk) => res.write(chunk));
}
module.exports = { convert };
