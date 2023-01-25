/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

/*
   DESCRIPTION
    This class is responsible for assert user by accessing idcs asserter endpoint.

   MODIFIED    (MM/DD/YY)
    xinnwang    12/06/16 - Creation
 */
'use strict';

// third party module
const request = require('request');
const cacheManager = require('cache-manager');
const async = require('async');

// local module
const Logger = require('./logger');

/**
 * @deprecated
 */
class Asserter {
  constructor(cacheOptions, metaDataManager, accessTokenManager) {
    this.logger = Logger.getLogger('Asserter');
    this.metaDataManager = metaDataManager;
    this.accessTokenManager = accessTokenManager;
    this.memoryCache = cacheManager.caching(cacheOptions);
  }

  /**
   * assert user by accessing idcs asserter endpoint 
   * @param {String} userName userName to assert
   * @param {Fucntion} callback callback(err, userAssertion) will be called at last
   */
  assertUser(userName, metadataUrl, callback) {
    this.logger.trace(`assertUser, userName: ${userName}, metadataUrl:${metadataUrl}`);

    let key = `${metadataUrl}?${userName}`;
    this.memoryCache.wrap(key, (cacheCallback) => {
      // download key from idcs server
      async.waterfall([(next) => {
        // fetch meta data from idcs server
        this.metaDataManager.fetchMetaData(metadataUrl, next);
      }, (metadata, next) => {
        // fetch oauth token
        this.accessTokenManager.fetchAccessToken(false, (err, token) => {
          next(err, metadata, token);
        });
      }, (metadata, token, next) => {
        let asserterEndpoint = metadata['access-configuration'].asserter_endpoint;
        // download pulic key
        this._assertUser(userName, token, asserterEndpoint, (err, data) => {
          if (err) {
            if (err.indexOf('Expired') > 0) {
              this.logger.warn(err);
              this.accessTokenManager.fetchAccessToken(true, (err, token) => {
                if (err) {
                  return next(err);
                }
                this._assertUser(userName, token, asserterEndpoint, next);
              });
            } else {
              return next(err);
            }
          } else {
            next(null, data);
          }
        });
      }], (err, data) => {
        if (err) {
          this.logger.error(err);
          cacheCallback(err);
        } else {
          this.logger.trace(`assertUser, data: ${JSON.stringify(data)}`);
          this.memoryCache.set(key, data);
          cacheCallback(null, data);
        }
      });
    }, callback);
  }
  _assertUser(userName, token, asserterEndpoint, callback) {
    // do post to idcs asserter endpoint
    request.post({
      url: asserterEndpoint,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: `{
        "mappingAttribute": "username",
        "mappingAttributeValue": "${userName}",
        "includeMemberships": true,
        "schemas": ["urn:ietf:params:scim:schemas:oracle:idcs:Asserter"]
      }`
    }, (err, res, body) => {
      if (!err && res.statusCode == 201) {
        let jsonObj = JSON.parse(body);
        this.logger.trace(`assertUser, jsonObj: ${JSON.stringify(jsonObj)}`);
        callback(null, jsonObj);
      } else {
        if (err) {
          this.logger.error(`assertUser, error: ${err}`);
          callback(err);
        } else {
          this.logger.error(`assertUser, error: ${body}`);
          callback(body);
        }
      }
    });
  }
}

module.exports = Asserter;
