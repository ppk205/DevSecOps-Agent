function search(req, res) {
  const pattern = new RegExp("^[a-z]+$");
  const hits = ["apple", "apricot", "banana"].filter((item) => pattern.test(item));
  res.send(hits);
}
module.exports = { search };
