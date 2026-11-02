async function proxy(req, res) {
  const r = await fetch("https://api.example.com/data");
  res.send(await r.text());
}
