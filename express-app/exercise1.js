const express = require('express')
const logger = require('morgan')

const app = express()
const port = 3000
app.use(logger('dev'))

// Middleware to detect Firefox
const detectFirefox = (req, res, next) => {
  const userAgent = req.headers['user-agent']
  req.isFirefox = userAgent.includes('Firefox')
  next()
}

// Apply the Firefox detection middleware to all routes
app.use(detectFirefox)

app.use(function(err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.get('/', (req, res) => {
  if (req.isFirefox) {
    res.send('hello firefox user')
  } else {
    res.send('hello world')
  }
})

app.get('/info', (req, res) => {
  const info = {
    name: 'my-express-server',
    description: 'My express server rules!'
  }
  res.json(info)
})

app.listen(port, () => {
  console.log(`Example app running in an HTTP server at TCP port ${port}`)
  console.log(`Test at http://localhost:${port}`)
})



