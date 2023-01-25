/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

const IDCSConstants = require('./idcsconstants');
const IDCSTokenVerifier = require('./idcstokenverifier');
const Logger = require('./logger');
const crypto = require('crypto');

var logger;

/**
 *
 * @param options
 * @constructor
 * @deprecated
 */
function IdcsTokenManager(options, cacheManager){
    logger = Logger.getLogger('IdcsTokenManager');
    this.options = options;
    this.cacheManager = cacheManager;
    if(cacheManager) {
        this.tokenCache = cacheManager.getTokenCache();
    }else {
        logger.trace("IdcsTokenManager, constructer didnt initialize cacheManager")
    }
}

/**
 * This method verifies idToken given and parse it and return IdToken Object
 * @param idToken idToken of User
 * @returns {*} decoded Id token as a JSON Object
 * @deprecated
 */
IdcsTokenManager.prototype.verifyIdToken = function (idToken) {
    logger.trace("verifyIdToken, idToken: "+ idToken);
    var tm = this;
    return new Promise(function(resolve, reject) {
        tm.verifyToken(idToken).then(function(token){
            resolve(token);
        }).catch(function(err){
            logger.error("verifyIdToken, error : "+err);
            reject(err);
        });
    });
};

/**
 * This method verifies AccessToken given and parse it and return Access Token Object
 * @param accessToken accessToken of User
 * @returns {*} decoded Access token as a JSON Object
 * @deprecated
 */
IdcsTokenManager.prototype.verifyAccessToken = function (accessToken) {
    logger.trace("verifyAccessToken, accessToken: "+ accessToken);
    var tm = this;
    return new Promise(function(resolve, reject) {
        tm.verifyToken(accessToken).then(function(token){
            resolve(token);
        }).catch(function(err){
            logger.error("verifyAccessToken, error : "+err);
            reject(err);
        });
    });
};

/**
 * Get token Expiry from Claim and calculate TTL
 * @param tokenDecoded
 * @returns {number}
 */
function getTTLfromClaim(tokenDecoded){
    logger.trace("getTTLfromClaim, tokenDecoded: "+ JSON.stringify(tokenDecoded));
    // Determine the TTL for the entry...
    var ttl = -1;
    if(tokenDecoded){
        var now = (new Date().getTime());
        var exp = tokenDecoded[IDCSConstants.TOKEN_CLAIM_EXPIRY];
        if(!exp){
            exp = 0;
        }
        ttl = (exp * 1000) - now;
    }
    return ttl;
}


/**
 * This method verifies token given and parse it and return decoded token
 * @param token accessToken or idToken of User
 * @returns {*} decoded token as a JSON Object
 * @deprecated
 */
IdcsTokenManager.prototype.verifyToken = function (token) {
    logger.trace("verifyToken, token: "+ token);
    var options = this.options;
    var level = options[IDCSConstants.TOKEN_VALIDATION_LEVEL] ? options[IDCSConstants.TOKEN_VALIDATION_LEVEL] : IDCSConstants.VALIDATION_LEVEL_FULL;
    var tokenCache = this.tokenCache;
    var cacheManager = this.cacheManager;
    return new Promise(function(resolve, reject) {
        var tv = new IDCSTokenVerifier(options, cacheManager);
        var key;
        key = crypto.createHash('sha256').update(token).digest('hex');

        if(tokenCache){
            if(key){
                logger.trace("verifyToken, checking key in cache , key = " + key);
                var claims = tokenCache.get(key);
                if(claims) {
                    logger.trace("verifyToken, getting claims from cache: "+ JSON.stringify(claims));
                    resolve(claims);
                    return;
                }else{
                    logger.trace("verifyToken, claims not found in cache will do validation");
                }
            }
        }
        tv.verifyJwtToken(token)
            .then(function(jwt){
                var ttl = getTTLfromClaim(jwt);
                if(IDCSConstants.VALIDATION_LEVEL_FULL == level || IDCSConstants.VALIDATION_LEVEL_NORMAL == level) {
                    var type = jwt[IDCSConstants.TOKEN_CLAIM_TOKEN_TYPE];
                    var isIdToken = type=='AT' ? false : true;
                    if(IDCSConstants.VALIDATION_LEVEL_FULL == level) {
                        tv.validateAudience(jwt, isIdToken).then(function(ret){
                            if(ret==true){
                                if(tokenCache && ttl > 0 && key) {
                                    logger.trace("verifyToken, putting in cache with key = " +key+" and ttl = "+ttl+ " the claims = "+JSON.stringify(jwt));
                                    tokenCache.set(key, jwt, ttl);
                                }
                                resolve(jwt);
                                return;
                            }else{
                                var err = new Error("Failed to Validate Audience with return false");
                                logger.error("verifyToken, error : "+err);
                                reject(err);
                                return;
                            }
                        }).catch(function(err){
                            var err = new Error("Failed to Validate Audience");
                            logger.error("verifyToken, error : "+err);
                            reject(err);
                            return;
                        });
                    }
                }else {

                    if(tokenCache && ttl > 0 && key) {
                        logger.trace("verifyToken, putting in cache with key = " +key+" and ttl = "+ttl+ " the claims = "+JSON.stringify(jwt));
                        tokenCache.set(key, jwt, ttl);
                    }
                    resolve(jwt);
                    return;
                }
            }).catch(function(err){
                logger.error("verifyToken, error : "+err);
                reject(err);
                return;
            })

    });
};

module.exports = IdcsTokenManager;

