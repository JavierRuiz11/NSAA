const express = require('express')
const logger = require('morgan')

const app = express()
const port = 3000
app.use(logger('dev'))

let a_middleware_function = function(req, res, next) {
  console.log('request invoked')
  next() 
}

app.use(function(err, req, res, next) {
    console.error(err.stack)
    res.status(500).send('Something broke!')
  })

app.use(a_middleware_function)

app.use('/someroute', a_middleware_function)

app.get('/', a_middleware_function)


app.get('/', (req, res) => {
  res.send('hello world!!')
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