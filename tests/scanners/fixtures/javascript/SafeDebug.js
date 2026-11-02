const logger = require("./logger");

function handle(req, res) {
  logger.info("request received");
  res.send("ok");
}
module.exports = { handle };
