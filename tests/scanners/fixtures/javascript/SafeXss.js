function show(req, res) {
  const name = req.query.name;
  document.getElementById("greet").textContent = name;
  res.send("ok");
}
