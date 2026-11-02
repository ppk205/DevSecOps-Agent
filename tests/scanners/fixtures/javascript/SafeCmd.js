const { execFile } = require("child_process");
function run(req, res) {
  execFile("ls", [req.query.dir], (err, out) => res.send(out));
}
