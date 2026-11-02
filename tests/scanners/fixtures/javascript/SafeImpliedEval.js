function run(task) {
  task();
}

function defer(req, res) {
  const task = String(req.query.task);
  setTimeout(() => run(task), 100);
  res.send("queued");
}
module.exports = { defer };
