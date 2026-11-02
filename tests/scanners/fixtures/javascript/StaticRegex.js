function search(req, res) {
  const pattern = new RegExp("^[a-z]+$");
  if (pattern.test(req.query.filter)) {
    res.send("match");
  } else {
    res.send("none");
  }
}
module.exports = { search };
