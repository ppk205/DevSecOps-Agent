const crypto = require("crypto");

function legacyHash(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}
module.exports = { legacyHash };
