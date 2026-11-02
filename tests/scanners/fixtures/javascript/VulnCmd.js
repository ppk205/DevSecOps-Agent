const { exec } = require("child_process");
function run(req, res) {
  exec("ls " + req.query.dir, (err, out) => res.send(out));
}
