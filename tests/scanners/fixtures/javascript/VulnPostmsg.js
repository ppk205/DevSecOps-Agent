function share(req, res) {
  const data = { user: req.query.user };
  window.postMessage(data, "*");
  res.send("shared");
}
module.exports = { share };
