function share(req, res) {
  const data = { user: req.query.user };
  window.postMessage(data, "https://app.example.com");
  res.send("shared");
}
module.exports = { share };
