const { randomBytes } = require("crypto");
function sessionToken() {
  return randomBytes(32).toString("hex");
}
module.exports = { sessionToken };
