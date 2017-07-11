/*
TODO's go here

TODO: Build inital API
TODO: Archive serving
TODO: Security EVERYWHERE
TODO: Socket.IO security also (damn thats alot of security)
TODO: Figure out how the heck cookies work
TODO: Better logging system because console.log is bad
TODO: do we even need chalk?
TODO: 4 oh 4 pages
*/

//DEPS
const express = require('express');
const app = express();
const http = require('http');
const fs = require('fs');
const chalk = require('chalk');
const crypto = require('crypto');
const compression = require('compression');
const favicon = require('serve-favicon')
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const hpp = require('hpp');
const morgan = require('morgan');
const helmet = require('helmet');

//CONFIG
const conf = {
  httpport: 80
}


//EXPRESSJS INIT
const server = http.createServer(app).listen(conf.httpport, function() {
    console.log("Express server listening on port " + conf.httpport);
});
server.listen(conf.httpport);

//SOCKET.IO INIT
const io = require('socket.io')(server)

//EXPRESSJS TWEAKS
app.set('etag', false);
app.disable('x-powered-by');

//EXPRESSJS MIDDLEWARE
app.use(compression())
app.use(cookieParser({
  secret: 'NintendoStopSuingMePlease'
}))
app.use(bodyParser.urlencoded({
  extended: false
}))
app.use(hpp())
//app.use(favicon('PATH_TO_FAVICON_HERE')))
app.use(morgan('tiny'))

//Security headers
app.use(helmet.frameguard())
app.use(helmet.ieNoOpen())
app.use(helmet.noSniff())
app.use(helmet.xssFilter())

app.get('/', function(req, res){
  res.sendFile(__dirname + '/web/index.html')
})
