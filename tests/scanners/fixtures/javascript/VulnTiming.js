const users = require("./users");

function login(req, res) {
  const account = users.findByName(req.body.name);
  if (account && req.body.password === account.password) {
    res.send("ok");
  } else {
    res.send("denied");
  }
}
module.exports = { login };
