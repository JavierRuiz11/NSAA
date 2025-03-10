const express = require('express')
const logger = require('morgan')

const app = express()
const port = 3000
app.use(logger('dev'))

// An example middleware function
let a_middleware_function = function(req, res, next) {
  console.log('request invoked')
  next() // Call next() so Express will call the next middleware function in the chain.
}

app.use(function(err, req, res, next) {
    console.error(err.stack)
    res.status(500).send('Something broke!')
  })

// Function added with use() for all routes and verbs
app.use(a_middleware_function)

// Function added with use() for a specific route
app.use('/someroute', a_middleware_function)

// A middleware function added for a specific HTTP verb and route
app.get('/', a_middleware_function)


app.get('/', (req, res) => {
  res.send('hello world')
});

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