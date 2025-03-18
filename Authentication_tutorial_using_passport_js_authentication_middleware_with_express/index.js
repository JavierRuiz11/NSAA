'use strict';

const express = require('express');
const logger = require('morgan');
const https = require('https');
const fs = require('fs');

const tlsServerKey = fs.readFileSync('./tls/webserver.key.pem');
const tlsServerCrt = fs.readFileSync('./tls/webserver.crt.pem');
const jwt = require('jsonwebtoken')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const cookieParser = require('cookie-parser');
const jwtSecret = require('crypto').randomBytes(16)
const JwtStrategy = require('passport-jwt').Strategy


const app = express();
app.use(logger('dev')); 
app.use(cookieParser());

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

  passport.use('jwtCookie', new JwtStrategy(
    {
      jwtFromRequest: (req) => {
        if (req && req.cookies) { return req.cookies.jwt }
        return null
      },
      secretOrKey: jwtSecret
    },
    function (jwtPayload, done) {
      if (jwtPayload.sub && jwtPayload.sub === 'walrus') {
        const user = {
          username: jwtPayload.sub,
          description: 'one of the users that deserve to get to this server',
          role: jwtPayload.role ?? 'user'
        }
        return done(null, user)
      }
      return done(null, false)
    }
  ))
  
app.use(express.urlencoded({ extended: true })) 
app.use(passport.initialize()) 



app.get('/',
    passport.authenticate(
      'jwtCookie',
      { session: false, failureRedirect: '/login' }
    ),
    (req, res) => {
      res.send(`Welcome to your private page, ${req.user.username}!`) 
    }
  )

app.get('/login',(req, res) => {
    res.sendFile('login.html', { root: __dirname }) 
  })  

app.post('/login',
    passport.authenticate('username-password', { failureRedirect: '/login', session: false }), 
    (req, res) => {
      const jwtClaims = {
        sub: req.user.username,
        iss: 'localhost:3000',
        aud: 'localhost:3000',
        exp: Math.floor(Date.now() / 1000) + 604800, 
        role: 'user' 
      }
  
      const token = jwt.sign(jwtClaims, jwtSecret)
  
      res.cookie('jwt', token, { httpOnly: true, secure: true }) 
      res.redirect('/')
  
      console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
      console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
    }
  )

app.get('/logout', (req, res) => {
    res.clearCookie('jwt');
    res.redirect('/login');
  });

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