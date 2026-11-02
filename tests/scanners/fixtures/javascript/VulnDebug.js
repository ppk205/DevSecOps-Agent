function handle(req, res) {
  debugger;
  console.log(req.query);
  res.send("ok");
}
module.exports = { handle };
