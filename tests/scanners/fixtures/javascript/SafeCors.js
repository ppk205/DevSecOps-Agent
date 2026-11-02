const cors = require("cors");

function setup(app) {
  app.use(cors({ origin: "https://app.example.com" }));
}

function locked(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "https://app.example.com");
  res.send("ok");
}
module.exports = { setup, locked };
