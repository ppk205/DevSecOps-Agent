function show(req, res) {
  const name = req.query.name;
  document.getElementById("greet").innerHTML = name;
  res.send("ok");
}
function legacy(req, res) {
  document.write(req.query.msg);
  res.send("ok");
}
