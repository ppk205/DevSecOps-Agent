const Order = require("../models/order");

function total(req, res) {
  Order.find({ code: Number(req.query.code) }).then((rows) => res.send(rows));
}
module.exports = { total };
