function defer(req, res) {
  setTimeout(req.query.task, 100);
  res.send("queued");
}
module.exports = { defer };
