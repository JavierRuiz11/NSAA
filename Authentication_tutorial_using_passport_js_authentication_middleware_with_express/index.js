'use strict';
const session = require('express-session');
const express = require('express');
const logger = require('morgan');
const https = require('https');
const fs = require('fs');
const { verify } = require('scrypt-mcf');
require('dotenv').config();
const tlsServerKey = fs.readFileSync('./tls/webserver.key.pem');
const tlsServerCrt = fs.readFileSync('./tls/webserver.crt.pem');
const jwt = require('jsonwebtoken')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const cookieParser = require('cookie-parser');
const jwtSecret = require('crypto').randomBytes(16)
const JwtStrategy = require('passport-jwt').Strategy
const GoogleStrategy = require('passport-google-oauth20').Strategy;


const app = express();
app.use(logger('dev')); 
app.use(cookieParser());

let users = [];  

app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true }  
}));

app.use(passport.session());

try {
  //const data = fs.readFileSync('./users_slow.json', 'utf-8'); 
  const data = fs.readFileSync('./users_fast.json', 'utf-8'); 
  users = JSON.parse(data); 
  if (!Array.isArray(users)) throw new Error("Invalid JSON format: Expected an array");
} catch (error) {
  console.error("Error loading users.json:", error.message);
  users = []; 
}

  passport.use('username-password', new LocalStrategy(
  {
    usernameField: 'username',
    passwordField: 'password',
    session: false
  },
  async function (username, password, done) {
    if (!Array.isArray(users)) {
      console.error("!!Error: users is not an array!!");
      return done(null, false);
    }

    const user = users.find(u => u.username === username);
    if (!user) {
      console.log("User not found!:", username);
      return done(null, false);
    }

    const isValid = await verify(password, user.password);
    if (!isValid) {
      console.log("Invalid password for:", username);
      return done(null, false);
    }

    return done(null, { username: user.username });
  }
  ));

  passport.use('google', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
  },
    (accessToken, refreshToken, profile, done) => {
      return done(null, profile);
    }
    ));

  passport.serializeUser((user, done) => {
      done(null, user); // Serializa el objeto de perfil completo
    });
    
  passport.deserializeUser((user, done) => {
      done(null, user); // Devuelve el usuario completo en la sesión
    });
    


  passport.use('jwtCookie', new JwtStrategy(
      {
        jwtFromRequest: (req) => req?.cookies?.jwt || null,
        secretOrKey: jwtSecret
      },
      (jwtPayload, done) => {
        // Acepta cualquier usuario con JWT válido
        return done(null, { username: jwtPayload.sub, role: jwtPayload.role || 'user' });
      }
    ));
    
  
app.use(express.urlencoded({ extended: true })) 
app.use(passport.initialize()) 
app.use(passport.session());

app.get('/auth/google', (req, res, next) => {
  console.log("Google Auth route accessed");
  next(); 
}, passport.authenticate('google', { scope: ['profile', 'email'] }));


app.get('/',
    passport.authenticate(
      'jwtCookie',
      { session: false, failureRedirect: '/login' }
    ),
    (req, res) => {
      console.log(req)
      res.send(`Welcome to your private page, ${req.user.username}!`) 
    }
  )

app.get('/login',(req, res) => {
    res.sendFile('login.html', { root: __dirname }) 
   })  

app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' , session: false }),
    function (req, res) {
      console.log(req.user)
      const jwtClaims = {
        sub: req.user.displayName,
        iss: 'localhost:3000',
        aud: 'localhost:3000',
        exp: Math.floor(Date.now() / 1000) + 604800, 
        role: 'user' 
      }
  
      const token = jwt.sign(jwtClaims, jwtSecret)
      console.log(token)
      res.cookie('jwt', token, { httpOnly: true, secure: true }) 
      res.redirect('/');

    }
  );

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
  
      //console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
      //console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
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