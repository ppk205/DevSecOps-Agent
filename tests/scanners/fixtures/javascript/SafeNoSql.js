const User = require("../models/user");

function lookup(req, res) {
  User.findOne({ username: String(req.query.user) }).then((user) => res.send(user));
}
module.exports = { lookup };
