const render = (req, res) => {
  const name = req.query.name;
  res.send('<h1>' + name + '</h1>');
};

module.exports = { render };
