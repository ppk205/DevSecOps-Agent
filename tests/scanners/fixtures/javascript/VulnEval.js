function calc(req, res) {
  res.send(String(eval(req.query.expr)));
}
