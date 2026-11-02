const crypto = require("crypto");
const users = require("./users");

function login(req, res) {
  const account = users.findByName(String(req.body.name));
  const expected = Buffer.from(account.password, "utf8");
  const actual = Buffer.from(String(req.body.password), "utf8");
  if (crypto.timingSafeEqual(expected, actual)) {
    res.send("ok");
  } else {
    res.send("denied");
  }
}
module.exports = { login };
