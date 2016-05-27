// Load modules.
var OAuth2Strategy = require('passport-oauth2')
var querystring = require('querystring')
var util = require('util')
var crypto = require('crypto')

function ensureToken (oauthIns) {
  var params = {
    appid: oauthIns._clientId,
    appsecret: oauthIns._clientSecret
  }
  var _ensure = function () {
    oauthIns._request('GET', oauthIns._getAccessTokenUrl() + '?' + querystring.stringify(params), null, null, null, function (err, data, res) {
      if (err) throw err
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
  options.tokenURL = options.tokenURL || 'https://oapi.dingtalk.com/gettoken'
  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-dingding'
  }

  OAuth2Strategy.call(this, options, verify)
  this.name = 'dingding'
  this._userProfileURL = options.userProfileURL || 'https://oapi.dingtalk.com/sns/getuserinfo'
  this._snsTokenURL = options.snsTokenURL || 'https://oapi.dingtalk.com/sns/get_sns_token'
  this._persistentTokenURL = options.persistentTokenURL || 'https://oapi.dingtalk.com/sns/get_persistent_code'
  this._host = options.host || 'https://oapi.dingtalk.com/sns'

  ensureToken(this._oauth2)
  this._oauth2.getAuthorizeUrl = function (params) {
    params = params || {}
    params['appid'] = this._clientId
    params['scope'] = 'snsapi_login'
    return this._baseSite + this._authorizeUrl + '?' + querystring.stringify(params)
  }
  this._oauth2.getOAuthAccessToken = function (code, params, callback) {
    params = params || {}
    params['client_id'] = this._clientId
    params['client_secret'] = this._clientSecret
    params['grant_type'] = 'authorization_code'
    // var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'authorization_code'
    params['code'] = code

    var self = this
    this._request('POST', this._persistentTokenURL + '?access_token=' + this.access_token, null, {tmp_auth_code: code}, null, function (err, data, res) {
      if (err) return callback(err)
      var openid = data.openid
      var unionid = data.unionid
      var persistent_code = data.persistent_code
      if (!openid || !persistent_code) return callback(new Error('getPersistentCode failed'))

      self._request('POST', this._snsTokenURL + '?access_token=' + this.access_token, {
        'Content-Type': 'application/json'
      }, {
        openid: openid,
        persistent_code: persistent_code
      }, null, function (err, data, res) {
        if (err) return callback(err)
        if (!data.sns_token) return callback(new Error('get sns_token failed'))
        callback(null, data.sns_token, null, {
          unionid: unionid,
          sns_token: sns_token
        })
      })
    })
  }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy)

Strategy.prototype.userProfile = function (params, done) {
  if (!params.sns_token) {
    return done(new Error('sns_token is required for userProfile api'))
  }
  this._oauth2._request('GET', this._userProfileURL + '?sns_token=' + params.sns_token , {"Content-Type": "application/json"}, null, null, function (err, body, res) {
    return done(err, body)
  })
}

// Expose constructor.
module.exports = Strategy
