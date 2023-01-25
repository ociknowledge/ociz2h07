/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

/*
   DESCRIPTION
    This class will take metadata, clientID, clientSecret as inputs to fetch 
    access token from idcs.

   MODIFIED    (MM/DD/YY)
    xinnwang    12/06/16 - Refacotoring
    junyhe      11/21/16 - Creation
 */
'use strict';

// third party module
const request = require('request');
const async = require('async');

// local module
const Logger = require('./logger');

/**
 * @deprecated
 */
class AccessTokenManager {
  constructor(metaDataManager, metadataUrl, oauthClientOptions) {
    this.logger = Logger.getLogger('AccessTokenManager');
    this.metaDataManager = metaDataManager;
    this.metadataUrl = metadataUrl;
    this.tokenTimeoutWindow = oauthClientOptions.tokenTimeoutWindow;
    this.cachedToken = null;

    let basicAuth = new Buffer(`${oauthClientOptions.clientId}:${oauthClientOptions.clientSecret}`).toString('base64');
    this.headers = {
      'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
      'Authorization': `Basic ${basicAuth}`
    };

    this.postData = {
      'grant_type': 'client_credentials',
      'scope': 'urn:opc:idm:__myscopes__'
    };

    this.logger.trace(`constructor, metadataUrl: ${metadataUrl}, oauthClientOptions:: ${JSON.stringify(oauthClientOptions)}`);
  }

  /**
   * Acquire oauth access token from idcs server 
   * @param {boolean} requestNewToken Indicates if new access token should be requested instead of using a cached token
   * @@param {Function} callback callback(err, token) will be called at last
  */
  fetchAccessToken(requestNewToken, callback) {
    this.logger.trace(`fetchAccessToken, requestNewToken: ${requestNewToken}`);
    if (!requestNewToken) {
      if (this.cachedToken) {
        if (Math.floor(Date.now() / 1000) >= this.cachedToken.exp + (this.tokenTimeoutWindow || 0)) {
          this.logger.warn('access token expired!');
        } else {
          this.logger.trace('return the cached token');
          return callback(null, this.cachedToken.token);
        }
      }
    }

    async.waterfall([(next) => {
      // fetch meta data from idcs server
      this.metaDataManager.fetchMetaData(this.metadataUrl, next);
    }, (metadata, next) => {
      let accessTokenUrl = metadata['openid-configuration'].token_endpoint;
      request.post({
        url: accessTokenUrl,
        headers: this.headers,
        form: this.postData
      }, (err, res, body) => {
        if (!err && res.statusCode == 200) {
          let jsonObj = JSON.parse(body);
          this.cachedToken = {
            token: jsonObj.access_token,
            exp: Math.floor(Date.now() / 1000) + jsonObj.expires_in
          };
          this.logger.trace(`fetchAccessToken, jsonObj: ${JSON.stringify(jsonObj)}, token: ${this.cachedToken}`);

          next(null, this.cachedToken.token);
        } else {
          this.cachedToken = null;
          if (err) {
            next(err);
          } else {
            this.logger.error(`fetchAccessToken, error: ${body}`);
            next(body);
          }
        }
      });
    }], (err, token) => {
      if (err) {
        this.logger.error(`fetchAccessToken, error: ${err}`);
        callback(err);
      } else {
        this.logger.trace(`fetchAccessToken, token: ${JSON.stringify(token)}`);
        callback(null, token);
      }
    });
  }
}

module.exports = AccessTokenManager;
