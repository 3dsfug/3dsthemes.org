/*
TODO's go here

TODO: Build inital API
TODO: Archive serving
TODO: Security EVERYWHERE
TODO: Socket.IO security also (damn thats alot of security)
TODO: Figure out how the heck cookies work
TODO: Better logging system because console.log is bad
TODO: do we even need chalk?
TODO: 4 oh 4 pages
*/

// DEPS
const PNG = require('pngjs').PNG
const splashTools = require('3ds-splash')
const promisify = require('promisify-node')
const fs = promisify('fs')
const crypto = require('crypto')
const taiPasswordStrength = require('tai-password-strength')
const multiparty = require('multiparty')
const path = require('path')
const accountFunctions = require('./accountFunctions.js')
const express = require('express')
const app = express()
const http = require('http')
const URL = require('url')
const bcrypt = require('bcrypt')
const compression = require('compression')
const cookieParser = require('cookie-parser')
const bodyParser = require('body-parser')
const multer = require('multer')
const hpp = require('hpp')
const morgan = require('morgan')
const helmet = require('helmet')
const session = require('express-session')
const MySQLStore = require('express-mysql-session')(session)
const QrCode = require('javascript-qrcode').QrCode
const minify = require('express-minify')
const tmp = require('tmp')
const minifyCache = tmp.dirSync().name
const archiver = require('archiver')
const jdenticon = require('jdenticon')
console.log(`Minify Cache: ${minifyCache}`)

// CONFIG
const conf = require(path.join(__dirname, 'config.json'))

// Data directories
fs.existsSync(conf.paths.themes) || fs.mkdirSync(conf.paths.themes)
fs.existsSync(conf.paths.splashes) || fs.mkdirSync(conf.paths.splashes)
fs.existsSync(conf.paths.badges) || fs.mkdirSync(conf.paths.badges)
fs.existsSync(conf.paths.previews) || fs.mkdirSync(conf.paths.previews)
fs.existsSync(conf.paths.niceThemes) || fs.mkdirSync(conf.paths.niceThemes)
fs.existsSync(conf.paths.niceBadges) || fs.mkdirSync(conf.paths.niceBadges)
fs.existsSync(conf.paths.niceSplashes) || fs.mkdirSync(conf.paths.niceSplashes)

// cookies
const sessionStore = new MySQLStore({
  host: conf.database.host,
  port: 3306,
  user: conf.database.user,
  password: conf.database.pass,
  database: conf.database.db,
  connectionLimit: 3,
  createDatabaseTable: true,
  schema: {
    tableName: 'sessions',
    columnNames: {
      session_id: 'session_id',
      expires: 'expires',
      data: 'data'
    }
  }
})

app.use(session(
  {
    store: sessionStore,
    secret: conf.cookie.secret,
    resave: false,
    saveUninitialized: false,
    httpOnly: false,
    name: '3ds-session',
    rolling: true,
    cookie: {
      secure: false,
      maxAge: 604800000
    }
  }
))

// MYSQL
const db = require('./dbConnection.js')

// EXPRESSJS INIT
const server = http.createServer(app).listen(conf.webserver.httpport, function () {
  console.log('Express server listening on port ' + conf.webserver.httpport)
})
server.listen(conf.webserver.httpport)

// VIEWS
app.set('views', './views')
app.set('view engine', 'pug')

// SOCKET.IO INIT
const io = require('socket.io')(server)

// EXPRESSJS TWEAKS
app.set('etag', false)
app.disable('x-powered-by')

// EXPRESSJS MIDDLEWARE
app.use(compression()) // Enables GZip compression
app.use(cookieParser())
app.use(bodyParser.urlencoded({ // Enables POST request parsing
  extended: false
}))
app.use(hpp()) // Protects against HPP (Google it)
// app.use(favicon('PATH_TO_FAVICON_HERE')))
app.use(morgan('tiny')) // HTTP Logger

// Security headers
app.use(helmet.frameguard()) // Anti-iframe
app.use(helmet.ieNoOpen()) // tbh i dont know what this is, but more security is better
app.use(helmet.noSniff()) // Anti mime sniff (thinking of disabling this)
app.use(helmet.xssFilter()) // XSS Protection (eh)

// minify and scss handling
app.use(minify({
  cache: minifyCache
}))

// Functions

function acceptsJSON (req) {
  return req.get('accept').indexOf('application/json') === 0
}

function send403 (req, res) {
  res.status(403).render('errors/403')
}

function send404 (req, res) {
  res.status(404).render('errors/404')
}

function send500 (req, res) {
  res.status(500).render('errors/500')
}

// Update last seen if logged in and set some template locals
app.all('*', function (req, res, next) {
  if (req.session && req.session.loggedIn === true) {
    accountFunctions.updateLastSeen(req.session.username)
  }

  res.locals.req = req
  res.locals.session = req.session
  res.locals.md5 = function (data) {
    return crypto.createHash('md5').update(data).digest("hex").toLowerCase()
  }

  next()
})

// Routes
app.get('/', function (req, res) {
  res.render('index')
})

app.get('/themes/', function (req, res) {
  res.render('themes')
})

app.get('/badges/', function (req, res) {
  res.render('badges')
})

app.get('/splashes/', function (req, res) {
  res.render('splashes')
})

app.all('(/account/*|/upload/*)', function (req, res, next) {
  if (req.session && req.session.loggedIn === true) {
    next()
  } else {
    if (req.url.match(/^\/account\/(?:login|register)/)) {
      next()
    } else {
      console.log(req.url)
      res.redirect('/account/login/?redirect=' + escape(req.url))
    }
  }
})

app.get('/account/', function (req, res) {
  accountFunctions.getUser(req.session.username).then(function (data) {
    res.render('account', {
      userData: data
    })
  }).catch(function (err) {
    console.warn(err)
    send500(req, res)
  })
})

app.get('/upload/', function (req, res) {
  res.render('upload')
})

function checkSplash (files, archive, variation, type, width, height) {
  console.log('checkSplash')
  return new Promise(function (resolve, reject) {
    console.log('checkSplashPromise')
    if (files[`splash${variation}${type}`] && files[`splash${variation}${type}`][0].size > 0) {
      console.log('filesize > 0')
      if (files[`splash${variation}${type}`][0].headers['content-type'] === 'image/png') {
        console.log('png')
        // it's a png
        fs.createReadStream(files[`splash${variation}${type}`][0].path)
          .pipe(new PNG({}))
          .on('parsed', function () {
            if (this.width !== width || this.height !== height) {
              // wrong resolution
              resolve(false)
            }

            splashTools.rgbaToBin({
              data: this.data,
              width: this.width,
              height: this.height
            }).then(function (binData) {
              archive.append(binData.data, { name: (type === 'Top' ? 'splash.bin' : 'splashbottom.bin') })
              resolve(binData.data)
            }).catch(function (err) {
              // there was an error converting the image
              console.error(err)
              reject(err)
            })
          })
      } else if (files[`splash${variation}${type}`][0].size === ((width * height) * 3)) {
        // assume it's a bin, it's the correct filesize
        console.log('archive file')
        archive.file(files[`splash${variation}${type}`][0].path, { name: (type === 'Top' ? 'splash.bin' : 'splashbottom.bin') })
        resolve(fs.readFileSync(files[`splash${variation}${type}`][0].path))
      } else {
        // it's something not suppored
        console.log('Not supported')
        resolve(null)
      }
    } else {
      console.log('file error')
      resolve(undefined)
    }
  })
}

function getSplashZipStream (variation, files) {
  console.log('getSplashZipStream')

  return new Promise(function (resolve, reject) {
    var archive = archiver('zip', {})

    Promise.all([
      checkSplash(files, archive, variation, 'Top', 400, 240),
      checkSplash(files, archive, variation, 'Bottom', 320, 240)
    ]).then(function (data) {
      console.log(data)
      if (data[0] === undefined && data[1] === undefined) {
        resolve(undefined)
      }
      if (data[0] === null || data[0] === null) {
        resolve(null)
      }
      if (data[0] === false || data[0] === false) {
        resolve(false)
      }
      if (data[0] || data[1]) {
        Promise.all([
          splashTools.binToRGBA({
            data: (data[0] ? data[0] : new Array(400 * 240 * 3))
          }),
          splashTools.binToRGBA({
            data: (data[1] ? data[1] : new Array(320 * 240 * 3))
          })
        ])
          .then(splashTools.generatePreviewPNG)
          .then(function (png) {
            resolve({
              zip: archive,
              png: png
            })
          })
      } else {
        resolve(null)
      }
    }).catch(function (err) {
      console.log('error', err)
      reject(err)
    })
  })
}

async function cleanupUploadedFiles (files) {
  for (var file in files) {
    for (var f = 0; f < files[file].length; f++) {
      if (await fs.exists(files[file][f].path)) {
        fs.unlink(files[file][f].path).catch(console.warn)
      }
    }
  }
}

function writeSplashZip (output, files, data, i) {
  return new Promise(function (resolve, reject) {
    data.on('end', function () {
      resolve()
    })
    data.on('error', function (err) {
      reject(err)
    })
    data.pipe(output)
    data.finalize()
  })
}

function writePNG (png, writeStream) {
  return new Promise(function (resolve, reject) {
    png.pack()
      .pipe(writeStream)
      .on('finish', resolve)
      .on('error', reject)
  })
}

app.post('/upload/', function (req, res) {
  var form = new multiparty.Form()

  form.parse(req, async function (err, fields, files) {
    if (err) {
      console.error(err)
      res.render('errors/500')
      return
    }

    var errors = []

    if(!(
      fields.name && fields.name[0].length > 1 && fields.name[0].legnth < 33 &&
      fields.shortDescription && fields.shortDescription[0].length > 0 &&
      fields.shortDescription[0].length < 65 && fields.nsfwLevel &&
      [0, 1, 2].indexOf(parseInt(fields.nsfwLevel)) !== -1
    )) {

    }
    if (!fields.name || fields.name[0].length < 1 || fields.name[0].length > 32) {
      errors.push('Invalid name')
    }
    if (!fields.shortDescription || fields.shortDescription[0].length < 1 || fields.shortDescription[0].length > 64) {
      errors.push('Invalid description')
    }
    if (!fields.nsfwLevel || [0, 1, 2].indexOf(parseInt(fields.nsfwLevel)) === -1) {
      errors.push('Invalid NSFW level')
    }

    var sanitizedTags = ''

    if (fields.tags && fields.tags[0].length > 0) {
      sanitizedTags = fields.tags[0].replace(/(\s*,\s*)+/g, ',').replace(/^,*(.*?),*$/, '$1')
    }

    if (fields.themeSubmit) {

    } else if (fields.badgeSubmit) {

    } else if (fields.splashSubmit) {
      try {
        var splashes = []
        for (var i = 1; i <= 10; i++) {
          var splash = await getSplashZipStream(i, files)
          if (splash === false) {
            errors.push('Wrong resolution for splash ' + i)
          } else if (splash === null) {
            errors.push('Wrong format for splash ' + i)
          } else if (splash) {
            splashes.push(splash)
          }
          if (errors.length > 0) {
            splashes = []
          }
        }
        if (splashes.length > 0) {
          var dbResult = await db.query('INSERT INTO `3dsthemes`.`themes` (`Name`, `Description`, `Author`, `Type`, `System`, `Submitted`, `NsfwLevel`, `Tags`, Published) VALUES (?,?,?,?,?,NOW(),?,?,?)', [
            fields.name[0],
            fields.shortDescription[0],
            req.session.userID,
            2,
            0,
            parseInt(fields.nsfwLevel[0]),
            sanitizedTags.toLowerCase(),
            (conf.autoApprove || req.session.permissions.autoapprove > 0) ? (new Date()) : 'NULL'
          ])
          for (var z = 0; z < splashes.length; z++) {
            await writeSplashZip(fs.createWriteStream(path.join(conf.paths.splashes, `${dbResult.insertId}v${z}.zip`)), files, splashes[z].zip, z + 1)
            await writePNG(splashes[z].png, fs.createWriteStream(path.join(conf.paths.previews, `${dbResult.insertId}v${z}.png`)))
          }
          res.render('uploadSuccess', {
            themeType: 'splash',
            variationCount: z
          })
        }
        cleanupUploadedFiles(files)
      } catch (err) {
        res.render('upload', { error: 'An unknown error occurred' })
        console.log(err)
        cleanupUploadedFiles(files)
      }
    } else {
      res.render('errors/500')
      res.end()
      return
    }
    if (errors.length > 0) {
      res.render('upload', { error: errors.join('\n\n') })
      return
    }
  })
})

app.get('/account/login', function (req, res) {
  if (req.session && req.session.loggedIn === true) {
    res.redirect('/')
  } else {
    res.render('login')
  }
})

app.get('/account/resend-activation', function (req, res) {
  if (req.session && req.session.username) {
    accountFunctions.getUser(req.session.username)
    .then(accountFunctions.sendVerifiationMail)
    .then(function (regData) {
      res.render('registerSuccess', {
        regData: regData
      })
    }).catch(function (err) {
      console.error(err)
      res.render('errors/500')
    })
  } else {
    res.render('errors/403')
  }
})

app.post('/account/login', function (req, res) {
  if (req.session && req.session.loggedIn === true) {
    res.redirect('/')
    return
  }

  if (req.body && req.body.username && req.body.password) {
    accountFunctions.checkCaptcha({
      username: req.body.username,
      password: req.body.password,
      returnResult: true,
      'g-recaptcha-response': req.body['g-recaptcha-response']
    }).then(accountFunctions.checkCredentials).then(function (data) {
      req.session.loggedIn = true
      req.session.username = data['username']
      req.session.userID = data['id']
      req.session.verificationCode = data['verificationCode']
      req.session.permissions = accountFunctions.getUserFlags(data['flags'])
      if (acceptsJSON(req)) {
        res.json({
          success: true,
          sessionID: req.sessionID
        })
      } else {
        res.redirect(req.body.redirect || '/')
      }
    }).catch(function (err) {
      if (err instanceof Error) {
        console.log(err)
        send500(req, res)
      }
      res.render('login', {
        error: err
      })
    })
  } else {
    res.render('login')
  }
})

app.get('/account/logout', function (req, res) {
  if (req.session) {
    req.session.destroy()
    res.clearCookie('3ds-session')
    res.redirect('/')
  }
})

app.get('/account/register', function (req, res) {
  if (req.session && req.session.loggedIn === true) {
    res.redirect('/')
  } else {
    res.render('register')
  }
})

app.post('/account/register', function (req, res) {
  accountFunctions.checkRegisterBody(req)
    .then(accountFunctions.checkCaptcha)
    .then(accountFunctions.checkUsername)
    .then(accountFunctions.checkEmail)
    .then(accountFunctions.checkPassword)
    .then(accountFunctions.registerUser)
    .then(function (regData) {
      if (acceptsJSON(req)) {
        res.json({
          success: true
        })
      } else {
        res.render('registerSuccess', {
          regData: regData
        })
      }
    })
    .catch(function (err) {
      if (acceptsJSON(req)) {
        res.json({ error: err })
      } else {
        res.render('register', {
          error: err
        })
      }
    })
})

app.get('/account/activate/:username/:code', function (req, res) {
  accountFunctions.activate({
    username: req.params.username,
    code: req.params.code
  }).then(function (data) {
    if (req.session.username === data['username']) {
      req.verificationCode = data['verificationCode']
      req.session.permissions = accountFunctions.getUserFlags(data['flags'])
    }

    if (acceptsJSON(req)) {
      res.json({success: true})
    } else {
      res.render('accountActivation')
    }
  }).catch(function (err) {
    if (err === false) {
      // code not found
      if (acceptsJSON(req)) {
        res.json({success: false})
      } else {
        send404(req, res)
      }
      return
    }

    // some other database error
    if (acceptsJSON(req)) {
      res.json({success: null})
    } else {
      send500(req, res)
    }
  })
})

// TODO: Post requests for different actions of changing user settings (email, password, so forth)

app.get('/json/qrcode.json', function (req, res) {
  if (req.query.level && ['L', 'M', 'Q', 'H'].indexOf(req.query.level) === -1) {
    send500(req, res)
    return
  }
  var qrcode = new QrCode(req.query.data, [req.query.level || 'H'])
  res.setHeader('Cache-Control', 'public, max-age=631152000')
  res.setHeader('Expires', new Date(Date.now() + 631152000000).toUTCString())
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.json(qrcode.getData())
})

app.get('/txt/qrcode.txt', function (req, res) {
  if (req.query.level && ['L', 'M', 'Q', 'H'].indexOf(req.query.level) === -1) {
    send500(req, res)
    return
  }
  var qrcode = new QrCode(req.query.data, [req.query.level || 'H'])
  res.setHeader('Cache-Control', 'public, max-age=631152000')
  res.setHeader('Expires', new Date(Date.now() + 631152000000).toUTCString())
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Content-Type', 'text/plain')

  res.send(qrcode.getData().map(function (e) { return e.join('') }).join(' '))
})

app.get('/images/identicons/:data', function (req, res) {
  res.setHeader('Content-Type', 'image/png')
  res.end(jdenticon.toPng(req.params.data, 128, 0))
})

app.use('/Errors/403', send403)
app.use('/Errors/404', send404)
app.use('/Errors/500', send500)
app.use('/data/themes/', express.static(path.join(conf.paths.themes)))
app.use('/data/splashes/', express.static(path.join(conf.paths.splashes)))
app.use('/data/badges/', express.static(path.join(conf.paths.badges)))
app.use('/data/previews/', express.static(path.join(conf.paths.previews)))
app.use(express.static(path.join(__dirname, 'web')))

app.use('/js/tai-password-strength', express.static(path.join(__dirname, 'node_modules', 'tai-password-strength')))
app.use('/js/javascript-qrcode', express.static(path.join(__dirname, 'node_modules', 'javascript-qrcode')))

app.all('*', function (req, res) {
  send404(req, res)
})

app.use(function (err, req, res, next) {
  console.log(err)
  if (err.status > 499 && err.status < 600) {
    res.status(err.status).render('errors/500', {
      req: req,
      session: req.session
    })
  } else {
    return next()
  }
})

/*
TODO: List themes (with filters)
TODO: User info
*/
