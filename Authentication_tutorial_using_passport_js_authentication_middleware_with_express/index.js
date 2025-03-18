'use strict';

const express = require('express');
const logger = require('morgan');
const https = require('https');
const fs = require('fs');

const tlsServerKey = fs.readFileSync('./tls/webserver.key.pem');
const tlsServerCrt = fs.readFileSync('./tls/webserver.crt.pem');

const app = express();
app.use(logger('dev')); // Log requests (GET, POST, ...)

app.get('/', (request, response) => {
    response.send('<h1>Hello!</h1>');
});

const httpsOptions = {
    key: tlsServerKey,
    cert: tlsServerCrt
};
var server = https.createServer(httpsOptions, app);

/**
 * Listen on provided port, on all network interfaces.
 */
server.listen(443);
server.on('listening', () => {
    console.log('HTTPS server running. Test it at https://127.0.0.1');
});