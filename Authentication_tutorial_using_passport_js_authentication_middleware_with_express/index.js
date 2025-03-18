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
      res.send(`Welcome to your private page, ${req.user.username}!`) // we can get the username from the req.user object provided by the jwtCookie strategy
    }
  )

app.get('/login',(req, res) => {
    res.sendFile('login.html', { root: __dirname }) 
  })  

app.post('/login',
    passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
    (req, res) => {
      // This is what ends up in our JWT
      const jwtClaims = {
        sub: req.user.username,
        iss: 'localhost:3000',
        aud: 'localhost:3000',
        exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
        role: 'user' // just to show a private JWT field
      }
  
      // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
      const token = jwt.sign(jwtClaims, jwtSecret)
  
      // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
      res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
      res.redirect('/')
  
      // And let us log a link to the jwt.io debugger for easy checking/verifying:
      console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
      console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
    }
  )

app.get('/logout', (req, res) => {
    // Clear the cookie
    res.clearCookie('jwt');
    // Redirect to the login page
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