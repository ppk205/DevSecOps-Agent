const jwt = require("jsonwebtoken");

function login(req, res) {
  const token = jwt.sign({ user: String(req.body.user) }, process.env.JWT_SECRET, {
    algorithm: "RS256",
    expiresIn: "1h",
  });
  res.send({ token });
}
module.exports = { login };
