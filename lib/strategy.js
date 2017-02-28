// Load modules.
var OAuth2Strategy = require('passport-oauth2')
var querystring = require('querystring')
var util = require('util')
var crypto = require('crypto')
var urllib = require('urllib')

function ensureToken (oauthIns) {
  var params = {
    appid: oauthIns._clientId,
    appsecret: oauthIns._clientSecret
  }
  var _ensure = function () {
    oauthIns._request('GET', oauthIns._getAccessTokenUrl() + '?' + querystring.stringify(params), {"Content-Type": "application/json"}, null, null, function (err, data, res) {
      if (err) throw err
      data = JSON.parse(data)
      if (data && data.access_token) {
        oauthIns.access_token = data.access_token
        setTimeout(_ensure, 60 * 1000 * 110)
      } else {
        setTimeout(_ensure, 2000)
      }
    })
  }
  _ensure()
}

function Strategy (options, verify) {
  options = options || {}
  options.authorizationURL = options.authorizationURL || 'https://oapi.dingtalk.com/connect/qrconnect'
  options.scopeSeparator = options.scopeSeparator || ','
  options.customHeaders = options.customHeaders || {}
  options.tokenURL = options.tokenURL || 'https://oapi.dingtalk.com/sns/gettoken'
  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-dingding'
  }

  OAuth2Strategy.call(this, options, verify)
  this.name = 'dingtalk'
  this._oauth2._userProfileURL = options.userProfileURL || 'https://oapi.dingtalk.com/sns/getuserinfo'
  this._oauth2._snsTokenURL = options.snsTokenURL || 'https://oapi.dingtalk.com/sns/get_sns_token'
  this._oauth2._persistentTokenURL = options.persistentTokenURL || 'https://oapi.dingtalk.com/sns/get_persistent_code'
  this._host = options.host || 'https://oapi.dingtalk.com/sns'

  ensureToken(this._oauth2)
  this._oauth2.getAuthorizeUrl = function (params) {
    params = params || {}
    params['appid'] = this._clientId
    params['scope'] = 'snsapi_login'
    return this._baseSite + this._authorizeUrl + '?' + querystring.stringify(params)
  }
  this._oauth2.getOAuthAccessToken = function (code, params, callback) {
    var self = this
    urllib.request(this._persistentTokenURL + '?access_token=' + this.access_token, {
      headers: {
        'Content-Type': 'application/json'
      },
      method: 'POST',
      dataType: 'json',
      data: {
        tmp_auth_code: code,
        access_token: this.access_token
      }
    }, function (err, data, res) {
      if (err) return callback(err)
      var openid = data.openid
      var unionid = data.unionid
      var persistent_code = data.persistent_code
      if (!openid || !persistent_code) return callback(new Error('getPersistentCode failed'))

      urllib.request(self._snsTokenURL + '?access_token=' + self.access_token, {
        headers: {
          'Content-Type': 'application/json'
        },
        method: 'POST',
        dataType: 'json',
        data: {
          openid: openid,
          persistent_code: persistent_code
        }
      }, function (err, data, res) {
        if (err) return callback(err)
        if (!data.sns_token) return callback(new Error('get sns_token failed'))
        callback(null, data.sns_token, null, {
          unionid: unionid,
          sns_token: data.sns_token
        })
      })
    })
  }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy)

Strategy.prototype.userProfile = function (params, done) {
  urllib.request(this._oauth2._userProfileURL + '?sns_token=' + params.sns_token, {
    headers: {
      'Content-Type': 'application/json'
    },
    dataType: 'json'
  }, function (err, data) {
    if (data.errcode) {
      e = new Error(data.errmsg)
      return done(e)
    }
    return done(err, data.user_info)
  })
}

// Expose constructor.
module.exports = Strategy
