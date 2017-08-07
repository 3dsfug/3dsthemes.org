const bcrypt = require('bcrypt')
const validator = require('validator')
const db = require('./dbConnection.js')
const taiPasswordStrength = require('tai-password-strength')
const passStrength = new taiPasswordStrength.PasswordStrength()
const crypto = require('crypto')
const bitFlags = require('./bitFlags.js')
const reCAPTCHA = require('recaptcha2')
const path = require('path')
const conf = require(path.join(__dirname, 'config.json'))
var recaptcha = new reCAPTCHA(conf.recaptcha2)

passStrength.addCommonPasswords(taiPasswordStrength.commonPasswords)

exports = {}

exports.getPasswordHash = function getPasswordHash (pass) {
  return new Promise(function (resolve, reject) {
    bcrypt.hash(pass, 10, function (err, hash) {
      if (err) {
        reject(err)
      } else {
        resolve(hash)
      }
    })
  })
}

exports.getVerificationCode = function getVerificationCode () {
  return crypto.randomBytes(16).toString('hex')
}

exports.checkRegisterBody = function (req) {
  return new Promise(function (resolve, reject) {
    console.log('checkRegisterBody')
    if (req.body && req.body.username && req.body.password && req.body.password2 && req.body.email) {
      console.log('checkRegisterBody: resolve')
      resolve({
        username: req.body.username,
        password: req.body.password,
        password2: req.body.password2,
        email: req.body.email,
        req: req
      })
    }
    console.log('checkRegisterBody: reject')
    reject('Invalid request data')
  })
}

exports.checkCaptcha = function checkCaptcha (regData) {
  console.log('checkCaptcha')
  return new Promise(function (resolve, reject) {
    // real captcha checking code will go here
    // for now, just always resolve.
    recaptcha.validate(regData['g-recaptcha-response']).then(function () {
    // validated and secure
      resolve(regData)
    }).catch(function (errorCodes) {
      // invalid
      reject('Invalid captcha')
    })
  })
}

exports.checkEmail = function checkEmail (regData) {
  return new Promise(function (resolve, reject) {
    console.log('checkEmail')
    if (validator.isEmail(regData.email)) {
      db.query('SELECT id FROM users WHERE email=?', [regData.email]).then(function (result) {
        if (result.length > 0) {
          reject('There is already an account with that email')
        } else {
          resolve(regData)
        }
      }).catch(function (err) {
        console.warn('Database error!', err)
        reject('An unknown error has occurred')
      })
    } else {
      reject('Invalid email')
    }
  })
}

exports.checkUsername = function checkUsername (regData) {
  return new Promise(function (resolve, reject) {
    console.log('checkUsername')
    if (regData.username.match(/[\x00-\x20\x80-\x9f\r\n\t\W\u1680\u180E\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u200B\u202F\u205F\u3000\uFEFF]/)) {
      reject('Username cannot contain spaces or non-Ascii characters')
    }
    if (regData.username.length < 4) {
      reject('Username is too short')
    }
    if (regData.username.length > 25) {
      reject('Username is too long')
    }

    db.query('SELECT id FROM users WHERE username=?', [regData.username]).then(function (result) {
      if (result.length > 0) {
        reject('Username already exists')
      } else {
        resolve(regData)
      }
    }).catch(function (err) {
      console.warn('Database error!', err)
      reject('An unknown error has occurred')
    })
  })
}

exports.checkPassword = function checkPassword (regData) {
  return new Promise(function (resolve, reject) {
    console.log('checkPassword')
    if (regData.password2 && (regData.password2 !== (regData.newPassword || regData.password))) {
      reject('Passwords do not match')
    }
    const check = passStrength.check(regData.newPassword || regData.password)
    if (check.commonPassword === true) {
      reject('Your password is too common')
    }
    if (check.strengthCode === 'VERY_WEAK') {
      console.log(check.strengthCode)
      // reject('Please use a stronger password')
    }
    resolve(regData)
  })
}

exports.registerUser = function registerUser (regData) {
  return new Promise(function (resolve, reject) {
    console.log('registerUser')
    regData.verificationCode = exports.getVerificationCode()
    const ip = regData.req.headers['x-forwarded-for'] || regData.req.connection.remoteAddress
    exports.getPasswordHash(regData.password).then(function (password) {
      db.query('INSERT INTO users (username, email, password, ip, verificationCode, bio, flags) VALUES (?, ?, ?, ?, ?, NULL, 0)', [
        regData.username,
        regData.email,
        password,
        ip,
        regData.verificationCode
      ]).then(function (results) {
        resolve(regData)
      }).catch(function (err) {
        console.warn('Database error!', err)
        reject('An unknown error has occurred')
      })
    }).catch(function (err) {
      console.log('Password error', err)
    })
  })
}

exports.activate = function activate (data) {
  return new Promise(function (resolve, reject) {
    console.log('activate')

    db.query('SELECT username FROM users WHERE username=? AND verificationCode=?', [data.username, data.code]).then(function (result) {
      if (result.length > 0) {
        db.query('UPDATE users SET flags = flags | 0b1 WHERE username=? AND verificationCode=?', [data.username, data.code], function (err, result, fields) {
          if (err) {
            console.warn('Database error!', err)
            reject('An unknown error occurred')
          } else {
            console.log(result)
            resolve(true)
          }
        })
      } else {
        reject(false)
      }
    }).catch(function (err) {
      console.error('Database error!', err)
      reject('An unknown error occurred')
    })
  })
}

exports.checkLoginBody = function checkLoginBody (body) {
  return new Promise(function (resolve, reject) {
    console.log('checkLoginBody')
    if (body && body.username && body.password) {
      resolve(body)
    } else {
      reject('Invalid request data')
    }
  })
}

exports.checkCredentials = function checkLogon (data) {
  return new Promise(function (resolve, reject) {
    console.log('checkCredentials')
    db.query('SELECT * FROM users WHERE username=?', [data.username]).then(function (result) {
      if (result.length > 0) {
        return bcrypt.compare(data.password, result[0].password).then(function (check) {
          if (check === true) {
            data.id = result[0].id
            resolve(data.returnResult ? result[0] : data)
          } else {
            reject('Invalid credentials')
          }
        }).catch(function (err) {
          console.warn('bcrypt error', err)
          reject('An unknown error occurred')
        })
      } else {
        reject('Invalid credentials')
      }
    }).catch(function (err) {
      console.log('Database error!', err)
      reject('An unknown error occurred')
    })
  })
}

exports.getUserFlags = function (bits) {
  console.log(bitFlags)
  var flagNames = Object.keys(bitFlags.account)
  bits = parseInt(bits)
  var output = {}

  if (isNaN(bits) || bits < 0) {
    return false
  }

  for (var i = 0; i < flagNames.length; i++) {
    var flag = flagNames[i]
    output[flag] = bits & bitFlags.account[flag]
    console.log(flag, bits, bitFlags.account[flag], output[flag])
  }

  return output
}

exports.getUser = function getUser (user) {
  return new Promise(function (resolve, reject) {
    db.query('SELECT * FROM users WHERE username=?', [user]).then(function (result) {
      if (result.length > 0) {
        resolve(result[0])
      } else {
        resolve(false)
      }
    }).catch(function (err) {
      console.warn('Database error!', err)
      reject(err)
    })
  })
}

exports.updateLastSeen = function updateLastSeen (username) {
  db.query('UPDATE users SET lastSeen=Now() WHERE username=?', [username]).catch(function (err) {
    console.warn('Database error!', err)
  })
}

exports.setPassword = function setPassword (data) {
  console.log('setPassword')
  return exports.checkPassword(data).then(function (data) {
    return new Promise(function (resolve, reject) {
      exports.getPasswordHash(data.newPassword || data.password).then(function (passwordHash) {
        db.query('UPDATE users SET password=?, passwordResetToken=NULL, passwordResetDate=NULL WHERE username=?', [passwordHash, data.username]).then(function (result) {
          if (result.affectedRows === 0) {
            reject('Invalid username')
          }
          resolve(data)
        }).catch(function (err) {
          console.warn('Database error!', err)
          reject('An unknown error occurred')
        })
      }).catch(reject)
    })
  })
}

exports.changePassword = function changePassword (data) {
  console.log('changePassword')
  return exports.checkCredentials(data).then(exports.setPassword)
}

exports.checkPasswordResetToken = function checkPasswordResetToken (data) {
  return new Promise(function (resolve, reject) {
    console.log('checkPasswordResetToken')
    db.query('SELECT * FROM users WHERE username=? AND passwordResetToken=?', [data.username]).then(function (result) {
      if (result.length > 0) {
        resolve(data)
      } else {
        reject('Invalid username / token combination')
      }
    }).catch(function (err) {
      console.warn('Database error!', err)
      reject('An unknown error occurred')
    })
  })
}

exports.resetPassword = function resetPassword (data) {
  console.log('resetPassword')
  return exports.checkPasswordResetToken(data).then(exports.checkPassword).then(exports.setPassword)
}

exports.generateResetToken = function generateResetToken (data) {
  return new Promise(function (resolve, reject) {
    console.log('generateResetToken')
    data.resetToken = exports.getVerificationCode()
    db.query('UPDATE users SET passwordResetToken=?, passwordResetDate=Now() WHERE email=?', [data.resetToken, data.email]).then(function (result) {
      if (result.affectedRows === 0) {
        reject('Invalid username')
      }
      resolve(data)
    }).catch(function (err) {
      console.warn('Database error!', err)
      reject('An unknown error has occurred')
    })
  })
}

exports.sendForgotPassword = function forgotPassword (data) {
  console.log('sendForgotPassword')
  return exports.generateResetToken(data).then(function (data) {
    // send the forgot password email
    throw new Error('Email not implemented!')
  })
}

module.exports = exports
