/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

/*
   DESCRIPTION
    This class is responsible for loading the public key and issuer which used to verify the id token.
    The data is cached in memory per tenant. 
    access token from idcs.

   MODIFIED    (MM/DD/YY)
    xinnwang    12/06/16 - Refacotoring
    junyhe      11/18/16 - Creation
 */
'use strict';

// system
const fs = require('fs');

// third party
const cacheManager = require('cache-manager');
const request = require('request');
const async = require('async');

// project modules
const Logger = require('./logger');

/**
 * @deprecated
 */
class KeyManager {
  constructor(cacheOptions, jwlsURI, accessTokenManager, metaDataManager) {
    this.logger = Logger.getLogger('KeyManager');
    this.memoryCache = cacheManager.caching(cacheOptions);
    this.jwlsURI = jwlsURI;
    this.accessTokenManager = accessTokenManager;
    this.metaDataManager = metaDataManager;
    this.logger.trace(`constructor, jwlsURI: ${jwlsURI}`);
  }

  /**
   * Get Public key for the tenant and the issuer, either from configured key file path or from the configured idcs server 
   * @param {String} metadataUrl metadata Url 
   * @param {Function} callback callback to return the key and issuer
   */
  fetchData(metadataUrl, callback) {
    this.logger.trace(`fetchJwks, metadataUrl: ${metadataUrl}`);

    // load jwk from memory cache firstly, if not found, load it from file or idcs server
    this.memoryCache.wrap(metadataUrl, (cacheCallback) => {
      // load from file
      if (this.jwlsURI) {
        return fs.readFile(this.jwlsURI, (err, jwks) => {
          if (err) {
            this.logger.error(err);
            cacheCallback(err);
          } else {
            let data = {
              jwks: jwks
            };
            this.memoryCache.set(metadataUrl, data);
            this.logger.trace(`fetchKey, set cache, metadataUrl: ${metadataUrl}, value: ${jwks}`);
            cacheCallback(null, data);
          }
        });
      } else {
        // download key from idcs server
        async.waterfall([(next) => {
          // fetch meta data from idcs server
          this.metaDataManager.fetchMetaData(metadataUrl, next);
        }, (metadata, next) => {
          // fetch oauth token
          this.accessTokenManager.fetchAccessToken(false, (err, token) => {
            next(err, metadata['openid-configuration'], token);
          });
        }, (openidConfiguration, token, next) => {
          let goNext = function(err, jwks) {
            next(err, jwks, openidConfiguration.issuer);
          };
          let jwks_uri = openidConfiguration.jwks_uri;
          this._downloadJwk(token, jwks_uri, (err, data) => {
            if (err) {
              if (err.indexOf('Expired') > 0) {
                this.logger.warn(err);
                this.accessTokenManager.fetchAccessToken(true, (err, token) => {
                  if (err) {
                    return goNext(err);
                  }
                  this._downloadJwk(token, jwks_uri, goNext);
                });
              } else {
                return goNext(err);
              }
            } else {
              goNext(null, data);
            }
          });
        }], (err, jwks, issuer) => {
          if (err) {
            this.logger.error(err);
            cacheCallback(err);
          } else {
            let data = {
              jwks: jwks,
              issuer: issuer
            };
            this.logger.trace(`fetchKey, data: ${JSON.stringify(data)}`);
            this.memoryCache.set(metadataUrl, data);
            cacheCallback(null, data);
          }
        });
      }
    }, callback);
  }

  /**
   * Download jwk file from idcs server 
   * @param {String} token oauth access token 
   * @param {Object} jwks_uri jwks uri of IDCS server
   * @param {Fucntion} callback callback(err, jwks) will be called at last
   */
  _downloadJwk(token, jwks_uri, callback) {
    this.logger.trace(`_downloadKey from server, jwks_uri: ${jwks_uri}, token: ${token}`);

    request({
      url: jwks_uri,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Authorization': `Bearer ${token}`,
      },
    }, (err, res, body) => {
      if (err) {
        return callback(`fail to download jwk from IDCS server: ${err}`);
      }

      if (res.statusCode === 200) {
        this.logger.trace(`_downloadKey, body: ${body}`);
        return callback(null, body);
      }

      if (res.statusCode === 401) {
        let error = res.headers['www-authenticate'];
        if (error) {
          return callback(`fail to download jwk from IDCS server: ${error}`);
        }
      }

      callback(body);
    });
  }
}

module.exports = KeyManager;
