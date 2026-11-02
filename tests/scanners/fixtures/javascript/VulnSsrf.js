async function proxy(req, res) {
  const r = await fetch(req.query.url);
  res.send(await r.text());
}
