//CONFIG
const conf = require('./config.json');
const mysql = require('promise-mysql');
module.exports = exports = mysql.createPool({connectionLimit: conf.database.connections, host: conf.database.host, user: conf.database.user, password: conf.database.pass, database: conf.database.db});
