const jwt = require("jsonwebtoken");

function login(req, res) {
  const token = jwt.sign({ user: req.body.user }, "secret");
  const legacy = jwt.sign({ user: "guest" }, req.body.key, { algorithm: "none" });
  res.send({ token, legacy });
}
module.exports = { login };
