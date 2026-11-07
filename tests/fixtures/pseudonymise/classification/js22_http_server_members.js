const http = require('http');

const server = http.createServer((request, response) => {
  response.writeHead(200);
  response.end('ok');
});
server.listen(8080);
