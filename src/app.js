import bodyParser from 'body-parser'
import cors from 'cors'
import express from 'express'
import fs from 'fs'
import http from 'http'
import yaml from 'yaml'
const path = require('path')
const createMiddleware = require('swagger-express-middleware')

import axios from 'axios'

import jwt from 'express-jwt'
import jwksRsa from 'jwks-rsa'

import pkg from '../package.json'

let swaggerFile = path.join(__dirname, 'swagger.yml')
const contents = fs.readFileSync(swaggerFile)
const swaggerDoc = yaml.parse(contents.toString('utf-8'))

const authMW = jwt({
  // Dynamically provide a signing key
  // based on the kid in the header and
  // the signing keys provided by the JWKS endpoint.
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: 'http://openid-walkthrough-session.eu.auth0.com/.well-known/jwks.json'
  }),

  audience: 'some-example-api',
  issuer: 'https://openid-walkthrough-session.eu.auth0.com/',
  algorithms: ['RS256']
})


let app = express()

swaggerDoc.info.version = pkg.version
if (process.env.NODE_ENV != 'production') {
  swaggerDoc.schemes = ['http']
}


if (process.env.NODE_ENV != 'production') {
  swaggerDoc.schemes = ['http']
}

createMiddleware(swaggerDoc, app, (error, middleware) => {

  //app.use(authMW)

  app.use(
    middleware.metadata(),
    middleware.CORS(),
    middleware.parseRequest(),
    middleware.validateRequest()
  )

  app.server = http.createServer(app)

  app.get('/base/tokens/access_token', authMW, (req, res) => {
    return res.json(req.user)
  })

  app.get('/base/tokens/id_token', authMW, async (req, res) => {
    const response = await axios.get(req.user.iss + 'userinfo', {
      headers: {
        Authorization: req.headers.authorization
      }
    })

    return res.json(response.data)
  })

  /*
  app.use(
    bodyParser.json({
      limit: Config.bodyLimit
    })
  )
  */

  app.get('/api-doc', (req, res) => {
    res.json(swaggerDoc)
  })

  app.server.listen(process.env.PORT || 8080, () => {
    //logger.info(`Started on port ${app.server.address().port}`)
  })
})

export default app
