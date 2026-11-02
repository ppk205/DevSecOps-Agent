const DOMPurify = require("dompurify");
function show(req, res) {
  document.getElementById("greet").innerHTML = DOMPurify.sanitize(req.query.name);
  res.send("ok");
}
