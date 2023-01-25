/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

const IDCSConstants = require('./idcsconstants');
const LRU = require('lru-cache');
const Logger = require('./logger');


var logger;
/**
 *@constructor
 */
function CacheManager(){
    logger = Logger.getLogger('CacheManager');
    var cacheOptions = { max: IDCSConstants.CACHE_MAX_SIZE_DEFAULT
        , length: function (n, key) { return n * 2 + key.length }
        , maxAge: IDCSConstants.CACHE_TTL_DEFAULT};
    logger.trace("initialize CacheManager");
    this.asserterCache = new LRU(cacheOptions);
    this.tokenCache = new LRU(cacheOptions);
    var scopeCacheOptions = { max: IDCSConstants.CACHE_MAX_SIZE_DEFAULT
        , length: function (n, key) { return n * 2 + key.length }
        , maxAge: IDCSConstants.FQS_RESOURCE_CACHE_TTL_DEFAULT};
    this.scopeCache = new LRU(scopeCacheOptions);
 }

CacheManager.prototype.getAsserterCache = function () {
    logger.trace("CacheManager, getAsserterCache");
    return this.asserterCache;
};

CacheManager.prototype.getTokenCache = function () {
    logger.trace("CacheManager, getTokenCache");
    return this.tokenCache;
};

CacheManager.prototype.getScopeCache = function () {
    logger.trace("CacheManager, getScopeCache");
    return this.scopeCache;
};

module.exports = CacheManager;

