/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

/*
   DESCRIPTION
    This class is responsible for loading meta data from idcs discovery url, 
    so that key file and oauth token url can be get from this metada.
    the meta data is cached per tenant in memory.

   MODIFIED    (MM/DD/YY)
    xinnwang    12/06/16 - Refacotoring
    junyhe      11/22/16 - Creation
 */
'use strict';

// third party module
const request = require('request');
const cacheManager = require('cache-manager');

// local module
const Logger = require('./logger');

/**
 * @deprecated
 */
class MetaDataManager {
  constructor(cacheOptions) {
    this.logger = Logger.getLogger('MetaDataManager');
    this.memoryCache = cacheManager.caching(cacheOptions);
  }

  /**
   * Acquire meta data from idcs server 
   * @param {String} idcsMetaDataUrl discovery url of idcs server 
   * @param {Fucntion} callback callback(err, metadata) will be called at last
   */
  fetchMetaData(idcsMetaDataUrl, callback) {
    this.logger.trace(`fetchMetaData, idcsMetaDataUrl: ${idcsMetaDataUrl}`);
    this.memoryCache.wrap(idcsMetaDataUrl, (cacheCallback) => {
      // load from idcs server
      request({
        url: idcsMetaDataUrl,
      }, (err, res, body) => {
        if (!err && res.statusCode == 200) {
          let jsonObj = JSON.parse(body);
          this.logger.trace(`fetchMetaData, jsonObj: ${JSON.stringify(jsonObj)}`);
          this.memoryCache.set(idcsMetaDataUrl, jsonObj);
          return cacheCallback(null, jsonObj);
        } else {
          if (err) {
            this.logger.error(`fetchMetaData, error: ${err}`);
            return cacheCallback(err);
          } else {
            this.logger.error(`fetchMetaData, error: ${body}`);
            return cacheCallback(body);
          }
        }
      });
    }, callback);
  }
}

module.exports = MetaDataManager;
