'use strict';

const express = require('express');
const logger = require('morgan');
const https = require('https');
const fs = require('fs');

const tlsServerKey = fs.readFileSync('./tls/webserver.key.pem');
const tlsServerCrt = fs.readFileSync('./tls/webserver.crt.pem');

const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy




const app = express();
app.use(logger('dev')); 

passport.use('username-password', new LocalStrategy(
    {
      usernameField: 'username', 
      passwordField: 'password', 
      session: false 
    },
    function (username, password, done) {
      if (username === 'walrus' && password === 'walrus') {
        const user = {
          username: 'walrus',
          description: 'the only user that deserves to get to this server'
        }
        return done(null, user) 
      }
      return done(null, false) 
    }
  ))

app.use(express.urlencoded({ extended: true })) 
app.use(passport.initialize()) 



app.get('/', (req, res) => {
    res.send('Welcome to your private page, user!')
  })

app.get('/login',(req, res) => {
    res.sendFile('login.html', { root: __dirname }) 
  })  

app.post('/login',
    passport.authenticate('username-password', { failureRedirect: '/login', session: false }), 
    (req, res) => {
      res.send(`Hello ${req.user.username}`)
    }
  )

app.use(function (err, req, res, next) {
    console.error(err.stack)
    res.status(500).send('Something broke!')
  })
  

const httpsOptions = {
    key: tlsServerKey,
    cert: tlsServerCrt
};
var server = https.createServer(httpsOptions, app);


server.listen(443);
server.on('listening', () => {
    console.log('HTTPS server running. Test it at https://127.0.0.1');
});