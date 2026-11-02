const cors = require("cors");

function setup(app) {
  app.use(cors());
}

function open(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.send("ok");
}
module.exports = { setup, open };
