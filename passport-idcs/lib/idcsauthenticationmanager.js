/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

const request = require('request');
const Promise = require('promise');
const querystring = require('querystring');
const jwt = require('jsonwebtoken');
const util = require('util');
const IdcsMetadataManager = require('./idcsmetadatamanager');
const IDCSConstants = require('./idcsconstants');
const CONSTANTS = require('./constants');
const CacheManager = require('./cachemanager');
const LRU = require('lru-cache');
const Logger = require('./logger');
const crypto = require('crypto');

var logger;

/**
 *  This class contains all the functionality of IDCS Authentication SDK.
 *  @param {Object}       options Configurations for idcs authentication manager
 * - IDCSHost             Required, IDCS host address. e.g. https://%tenant%.idcspool0.identity.c9dev0.oraclecorp.com
 * - ClientTenant         Required, OAuth client tenant
 * - ClientId             Required, OAuth client id
 * - ClientSecret         Required, OAuth client secret
 * - AudienceServiceUrl   Required, for token validation
 * - TokenIssuer          Required, for token validation
 * - CrossTenant          Optional, set true for Cross tenant use cases
 * - TokenClockSkew       Optional, number of seconds to tolerate when checking the nbf and exp claims, to deal with small clock differences among different servers, default: 120
 * - LogLevel             Optional, set logging level, default level: warn
 * @access public
 * @constructor
 */
function IdcsAuthenticationManager(options) {
    this.options = options;
    Logger.setLevel(this.options[CONSTANTS.LOG_LEVEL]);
    logger = Logger.getLogger('IdcsAuthenticationManager');
    this.IdcsTokenManager = require('./idcstokenmanager');
    this.IdcsUserAssert = require('./idcsuserassert');


    this.cacheManager = new CacheManager();
    this.tokenManager = new this.IdcsTokenManager(this.options, this.cacheManager);
    this.userAssert = new this.IdcsUserAssert(this.options, this.cacheManager);

}

/**
 * This method returns the Logout URL for the tenant
 * @param postLogoutRedirectUri The postLogoutRedirectUri where post logout would be sent back
 * @param state The state to be passed to OAUTH provider
 * @param idTokenHint The token used to inititate logout
 * @returns {Promise} when fulfilled return A complete formed URL at which the browser should hit to logout else returns error
 */
IdcsAuthenticationManager.prototype.getLogoutUrl = function (postLogoutRedirectUri, state, idTokenHint){
    var tokenCache = this.cacheManager.getTokenCache();
    var mdm = new IdcsMetadataManager(this.options);
    return new Promise(function(resolve, reject) {

        if(!idTokenHint){
            var err = new Error("token is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        var key = crypto.createHash('sha256').update(idTokenHint).digest('hex');
        tokenCache.del(key);
        mdm.getMetadata().then(function (md) {
            var params = {};
            if (postLogoutRedirectUri) {
                params[IDCSConstants.PARAM_POST_LOGOUT_URI] = postLogoutRedirectUri;
            }
            if (state) {
                params[IDCSConstants.PARAM_STATE] = state;
            }
            if (idTokenHint) {
                params[IDCSConstants.PARAM_IDTOKEN_HINT] = idTokenHint;
            }

            var logoutUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATOIN_ENDSESSION_ENDPOINT];
            if (params) {
                var query = querystring.stringify(params);
                logoutUrl += "?" + query;
                logger.trace("logoutUrl = " + logoutUrl);

            }
            resolve(logoutUrl);
        }).catch(function (err) {
            logger.error("logoutUrl, error:" + err);
            reject(err);
        });
    });
};

/**
 * This method returns the Authorization Code URL for the tenant for the BaseUrl present in options
 * @param redirectUri The redirectUri where authorization code would be sent back
 * @param scope The scopes for which the authorization code is returned
 * @param state The state to be passed to OAUTH provider
 * @param responseType The response type required from OAUTH Provider
 * @param nonce The nonce is used for openId verification to prevent replay attacks. Use other method for non openid flow
 * @returns {Promise} when fulfilled return A complete formed URL at which the browser should hit to get the authorization code else returns error
 */
IdcsAuthenticationManager.prototype.getAuthorizationCodeUrl = function (redirectUri, scope, state, responseType, nonce) {
    logger.trace("getAuthorizationCodeUrl, redirectUri: "+ redirectUri+ ", scope:"+ scope +", state: " + state + ", responseType:" + responseType + ", nonce:"+nonce);
    var options = this.options;
    return new Promise(function(resolve, reject) {
        if(!redirectUri || redirectUri==''){
            var err = new Error("Redirect Uri is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        if(!options[IDCSConstants.CLIENT_ID] || options[IDCSConstants.CLIENT_ID]==''){
            var err = new Error("Client Id is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        var mdm = new IdcsMetadataManager(options);
        mdm.getMetadata().then(function (md) {
            var params = {};
            params[IDCSConstants.PARAM_CLIENT_ID] = options[IDCSConstants.CLIENT_ID];
            params[IDCSConstants.PARAM_REDIRECT_URI] = redirectUri;
            if(responseType)
                params[IDCSConstants.PARAM_RESPONSE_TYPE] = responseType;
            else
                params[IDCSConstants.PARAM_RESPONSE_TYPE] = IDCSConstants.RESPONSE_TYPE_CODE;
            if(scope) {
                params[IDCSConstants.PARAM_SCOPE] = scope;
                if(nonce && scope.indexOf(IDCSConstants.OPEN_ID) >= 0){
                    params[IDCSConstants.PARAM_NONCE] = nonce;
                }
            }
            if(state){
                params[IDCSConstants.PARAM_STATE] = state;
            }
            var authzUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATION_AUTHORIZATION_ENDPOINT];
            var query = querystring.stringify(params);
            authzUrl+="?" + query;
            logger.trace("authzURL = "+authzUrl);
            resolve(authzUrl)
        }).catch(function (err) {
            logger.error("authzURL, error:"+err);
            reject(err);
        })
    });
};

/**
 * This methods fetched access token for the authorization code flow
 * @param code The authorization code sent by OAUTH provider
 * @param nonce The nonce is used for openId verification to prevent replay attacks. Use other method for non openid flow
 * @returns {Promise} when fulfilled returns JSON containing claims returned in Authentication else returns error
 */
IdcsAuthenticationManager.prototype.authorizationCode = function(code, nonce){
    logger.trace("authorizationCode, code: "+ code + ", nonce:" +nonce);
    var options = this.options;
    return new Promise(function(resolve, reject){
        if(!code || code==''){
            var err = new Error("Authorization Code is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        if(!options[IDCSConstants.CLIENT_ID] || options[IDCSConstants.CLIENT_ID]==''){
            reject(new Error("Client Id is Empty"));
            return;
        }
        if(!options[IDCSConstants.CLIENT_SECRET] || options[IDCSConstants.CLIENT_SECRET]==''){
            var err = new Error("Client Secret is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        var mdm = new IdcsMetadataManager(options);
        mdm.getMetadata().then(function(md){
            var tokenUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATION_TOKEN_ENDPOINT];
            var params = {};
            params[IDCSConstants.PARAM_GRANT_TYPE] = IDCSConstants.GRANT_AUTHZ_CODE;
            params[IDCSConstants.PARAM_CODE] = code;
            var basicAuth = new Buffer(options[IDCSConstants.CLIENT_ID] + ":" + options[IDCSConstants.CLIENT_SECRET]).toString('base64');
            var headers = {};
            headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.WWW_FORM_ENCODED;
            headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BASIC, basicAuth);
            logger.trace("sending request for url "+ tokenUrl + " with headers = "+ JSON.stringify(headers)+ " and params  = "+ JSON.stringify(params));
            request.post({
                url: tokenUrl,
                headers: headers,
                form: params
            }, function (err, res, body) {
                if (!err && res.statusCode == 200) {
                    var jsonObj = JSON.parse(body);
                    logger.trace("responde = "+ body);
                    if(jsonObj.id_token){
                        var tokenDecoded = jwt.decode(jsonObj.id_token, {
                            complete: true
                        });
                        if(tokenDecoded.payload.nonce){
                            if(!nonce){
                                var err = new Error("authorizationCode : Nonce should not be null");
                                logger.error(err);
                                reject(err);
                                return;
                            }
                            if(tokenDecoded.payload.nonce !== nonce){
                                var err = new Error("authorizationCode : Nonce didn't match.");
                                logger.error(err);
                                reject(err);
                                return;
                            }
                        }
                    }
                    resolve(jsonObj);
                    return;
                } else {
                    if (err) {
                        logger.error("authorizationCode, error: "+err);
                        reject(err);
                    } else {
                        logger.error("authorizationCode, error: "+body);
                        reject(new Error(body));
                    }
                }
            });
        }).catch(function(err){
            logger.error("authorizationCode, error:"+err);
            reject(err);
        })
    });
};

/**
 * This methods fetched access token for the resource owner OAUTH flow
 * @param username Login Id used to do login
 * @param password Password of the User
 * @param scope List of scopes for which access token is required
 * @returns {Promise} when fulfilled returns JSON containing claims returned in Authentication else returns error
 */
IdcsAuthenticationManager.prototype.resourceOwner = function(username, password, scope){
    logger.trace("resourceOwner, username: "+ username + ", password:" +password + ", scope:" +scope);
    var options = this.options;
    return new Promise(function(resolve, reject){
        if(!username || username==''){
            var err = new Error("Username is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        if(!password || password==''){
            var err = new Error("Password is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        if(!options[IDCSConstants.CLIENT_ID] || options[IDCSConstants.CLIENT_ID]==''){
            var err = new Error("Client Id is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        if(!options[IDCSConstants.CLIENT_SECRET] || options[IDCSConstants.CLIENT_SECRET]==''){
            var err = new Error("Client Secret is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        var mdm = new IdcsMetadataManager(options);
        mdm.getMetadata().then(function(md){
            var tokenUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATION_TOKEN_ENDPOINT];
            var params = {};
            params[IDCSConstants.PARAM_GRANT_TYPE] = IDCSConstants.GRANT_PASSWORD;
            params[IDCSConstants.PARAM_USERNAME] = username;
            params[IDCSConstants.PARAM_PASSWORD] = password;
            if(scope){
                params[IDCSConstants.PARAM_SCOPE] = scope;
            }
            var basicAuth = new Buffer(options[IDCSConstants.CLIENT_ID] + ":" + options[IDCSConstants.CLIENT_SECRET]).toString('base64');
            var headers = {};
            headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.WWW_FORM_ENCODED;
            headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BASIC, basicAuth);
            logger.trace("sending request for url "+ tokenUrl + " with headers = "+ JSON.stringify(headers)+ " and params  = "+ JSON.stringify(params));
            request.post({
                url: tokenUrl,
                headers: headers,
                form: params
            }, function (err, res, body) {
                if (!err && res.statusCode == 200) {
                    logger.trace("response = " + body);
                    var jsonObj = JSON.parse(body);
                    resolve(jsonObj);
                } else {
                    if (err) {
                        logger.error("resourceOwner, error: "+ err);
                        reject(err);
                    } else {
                        logger.error("resourceOwner, error: "+ body);
                        reject(new Error(body));
                    }
                }
            });
        }).catch(function(err){
            logger.error("resourceOwner, error:"+err);
            reject(err);
        })
    });
};

/**
 * This methods fetched access token for the refresh token OAUTH flow
 * @param refreshToken The refresh token to fetch access token
 * @param scope List of scopes for which access token is required
 * @returns {Promise} when fulfilled returns JSON containing claims returned in Authentication else returns error
 */
IdcsAuthenticationManager.prototype.refreshToken = function (refreshToken, scope){
    logger.trace("refreshToken, refreshToken: "+ refreshToken + ", scope:" +scope);
    var options = this.options;
    return new Promise(function(resolve, reject){
        if(!refreshToken || refreshToken==''){
            var err = new Error("Refresh Token is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        if(!options[IDCSConstants.CLIENT_ID] || options[IDCSConstants.CLIENT_ID]==''){
            var err = new Error("Client Id is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        if(!options[IDCSConstants.CLIENT_SECRET] || options[IDCSConstants.CLIENT_SECRET]==''){
            var err = new Error("Client Secret is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        var mdm = new IdcsMetadataManager(options);
        mdm.getMetadata().then(function(md){
            var tokenUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATION_TOKEN_ENDPOINT];
            var params = {};
            params[IDCSConstants.PARAM_GRANT_TYPE] = IDCSConstants.GRANT_REFRESH_TOKEN;
            params[IDCSConstants.PARAM_REFRESH_TOKEN] = refreshToken;
            if(scope){
                params[IDCSConstants.PARAM_SCOPE] = scope;
            }
            var basicAuth = new Buffer(options[IDCSConstants.CLIENT_ID] + ":" + options[IDCSConstants.CLIENT_SECRET]).toString('base64');
            var headers = {};
            headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.WWW_FORM_ENCODED;
            headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BASIC, basicAuth);
            logger.trace("sending request for url "+ tokenUrl + " with headers = "+ JSON.stringify(headers)+ " and params  = "+ JSON.stringify(params));
            request.post({
                url: tokenUrl,
                headers: headers,
                form: params
            }, function (err, res, body) {
                if (!err && res.statusCode == 200) {
                    logger.trace("response = "+body);
                    var jsonObj = JSON.parse(body);
                    resolve(jsonObj);
                } else {
                    if (err) {
                        logger.error("refreshToken, error: "+ err);
                        reject(err);
                    } else {
                        logger.error("refreshToken, error: "+body);
                        reject(new Error(body));
                    }
                }
            });
        }).catch(function(err){
            logger.error("refreshToken, error:"+err);
            reject(err);
        })
    });
};

/**
 * This methods fetched access token for the client credentials OAUTH flow
 * @param scope List of scopes for which access token is required
 * @returns {Promise} when fulfilled returns JSON containing claims returned in Authentication else returns error
 */
IdcsAuthenticationManager.prototype.clientCredentials = function (scope){
    logger.trace("clientCredentials, scope:" +scope);
    var options = this.options;
    return new Promise(function(resolve, reject){
        if(!options[IDCSConstants.CLIENT_ID] || options[IDCSConstants.CLIENT_ID]==''){
            var err = new Error("Client Id is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        if(!options[IDCSConstants.CLIENT_SECRET] || options[IDCSConstants.CLIENT_SECRET]==''){
            var err = new Error("Client Secret is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        var mdm = new IdcsMetadataManager(options);
        mdm.getMetadata().then(function(md){
            var tokenUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATION_TOKEN_ENDPOINT];
            var params = {};
            params[IDCSConstants.PARAM_GRANT_TYPE] = IDCSConstants.GRANT_CLIENT_CRED;
            params[IDCSConstants.PARAM_SCOPE] = scope;
            var basicAuth = new Buffer(options[IDCSConstants.CLIENT_ID] + ":" + options[IDCSConstants.CLIENT_SECRET]).toString('base64');
            var headers = {};
            headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.WWW_FORM_ENCODED;
            headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BASIC, basicAuth);
            logger.trace("sending request for url "+ tokenUrl + " with headers = "+ JSON.stringify(headers)+ " and params  = "+ JSON.stringify(params));
            request.post({
                url: tokenUrl,
                headers: headers,
                form: params
            }, function (err, res, body) {
                if (!err && res.statusCode == 200) {
                    logger.trace("response = "+body);
                    var jsonObj = JSON.parse(body);
                    resolve(jsonObj)
                } else {
                    if (err) {
                        logger.error("clientCredentials, error: "+ err);
                        reject(err);
                    } else {
                        logger.error("clientCredentials, error: "+body);
                        reject(new Error(body));
                    }
                }
            });
        }).catch(function(err){
            logger.error("clientCredentials, error:"+err);
            reject(err);
        })
    });
};

/**
 * This method fetches access token using the Client Assertion OAUTH flow
 * @param userAssertion User Assertion as JSON WEB Token
 * @param clientAssertion Client Assertion as JSON WEB Token
 * @param scope List of scopes for which access token is required
 * @returns {Promise} when fulfilled returns JSON containing claims returned in Authentication else returns error
 */
IdcsAuthenticationManager.prototype.clientAssertion = function (userAssertion, clientAssertion, scope){
    logger.trace("clientAssertion, userAssertion: "+ userAssertion +", clientAssertion:" + clientAssertion+ ", scope:" +scope);
    var options = this.options;
    return new Promise(function(resolve, reject){
        if(!clientAssertion || clientAssertion==''){
            var err = new Error("Client Assertion is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        if(!userAssertion || userAssertion==''){
            var err = new Error("User Assertion is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        var mdm = new IdcsMetadataManager(options);
        mdm.getMetadata().then(function(md){
            var tokenUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATION_TOKEN_ENDPOINT];
            var params = {};
            params[IDCSConstants.PARAM_GRANT_TYPE] = IDCSConstants.GRANT_ASSERTION;
            params[IDCSConstants.PARAM_ASSERTION] = userAssertion;
            params[IDCSConstants.PARAM_CLIENT_ID] = options[IDCSConstants.CLIENT_ID];
            params[IDCSConstants.PARAM_CLIENT_ASSERTION] = clientAssertion;
            params[IDCSConstants.PARAM_CLIENT_ASSERTION_TYPE] = IDCSConstants.ASSERTION_TYPE_JWT;
            if(scope){
                params[IDCSConstants.PARAM_SCOPE] = scope;
            }
            var headers = {};
            headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.WWW_FORM_ENCODED;
            logger.trace("sending request for url "+ tokenUrl + " with headers = "+ JSON.stringify(headers)+ " and params  = "+ JSON.stringify(params));
            request.post({
                url: tokenUrl,
                headers: headers,
                form: params
            }, function (err, res, body) {
                if (!err && res.statusCode == 200) {
                    logger.trace("response = " + body);
                    var jsonObj = JSON.parse(body);
                    resolve(jsonObj);
                } else {
                    if (err) {
                        logger.error("clientAssertion, error: "+err);
                        reject(err);
                    } else {
                        logger.error("clientAssertion, error: "+body);
                        reject(new Error(body));
                    }
                }
            });
        }).catch(function(err){
            logger.error("clientAssertion, error: "+err);
            reject(err);
        })
    });
};

/**
 * This method fetches access token using the User Assertion OAUTH flow
 * @param userAssertion User Assertion as JSON WEB Token
 * @param scope List of scopes for which access token is required
 * @returns {Promise} when fulfilled returns JSON containing claims returned in Authentication else returns error
 */
IdcsAuthenticationManager.prototype.userAssertion = function (userAssertion, scope){
    logger.trace("userAssertion, userAssertion: "+ userAssertion + ", scope:" +scope);
    var options = this.options;
    return new Promise(function(resolve, reject){
        if(!userAssertion || userAssertion==''){
            var err = new Error("User Assertion is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        if(!options[IDCSConstants.CLIENT_ID] || options[IDCSConstants.CLIENT_ID]==''){
            var err = new Error("Client Id  is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        if(!options[IDCSConstants.CLIENT_SECRET] || options[IDCSConstants.CLIENT_SECRET]==''){
            var err = new Error("Client Secret  is Empty");
            logger.error(err);
            reject(err);
            return;
        }
        var mdm = new IdcsMetadataManager(options);
        mdm.getMetadata().then(function(md){
            var tokenUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATION_TOKEN_ENDPOINT];
            var params = {};
            params[IDCSConstants.PARAM_GRANT_TYPE] = IDCSConstants.GRANT_ASSERTION;
            params[IDCSConstants.PARAM_ASSERTION] = userAssertion;
            if(scope){
                params[IDCSConstants.PARAM_SCOPE] = scope;
            }
            var basicAuth = new Buffer(options[IDCSConstants.CLIENT_ID] + ":" + options[IDCSConstants.CLIENT_SECRET]).toString('base64');
            var headers = {};
            headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.WWW_FORM_ENCODED;
            headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BASIC, basicAuth);
            logger.trace("sending request for url "+ tokenUrl + " with headers = "+ JSON.stringify(headers)+ " and params  = "+ JSON.stringify(params));
            request.post({
                url: tokenUrl,
                headers: headers,
                form: params
            }, function (err, res, body) {
                if (!err && res.statusCode == 200) {
                    logger.trace("response : "+body);
                    var jsonObj = JSON.parse(body);
                    resolve(jsonObj);
                } else {
                    if (err) {
                        logger.error("userAssertion, error: "+err);
                        reject(err);
                    } else {
                        logger.error("userAssertion, error: "+body);
                        reject(new Error(body));
                    }
                    }
            });
        }).catch(function(err){
            logger.error("userAssertion, error: "+err);
            reject(err);
        })
    });
};

/**
 * This method produces a signed JWT from the given claims
 * @param privateKey RSA Private Key to sign the assertion
 * @param headers A map of headers for Signed token. Claims kid or x5t are mandatory
 * @param claims A map of claims for Signed token. Claims sub,exp,aud are mandatory
 * @param alg The algorithm used to sign. Default is RS256
 * @returns {Promise} Serialized Signed Json Web Token else returns error
 */
IdcsAuthenticationManager.prototype.generateAssertion = function(privateKey, headers, claims, alg){
    logger.trace("generateAssertion, privateKey: "+ privateKey + ", headers:" +headers + ", claims:" +claims+ ", alg:" +alg);
    return new Promise(function(resolve, reject) {
        if(!claims[IDCSConstants.TOKEN_CLAIM_SUBJECT]){
            var err = new Error("Subject claim is missing");
            logger.error(err);
            reject(err);
            return;
        }
        if(!claims[IDCSConstants.TOKEN_CLAIM_AUDIENCE]){
            var err = new Error("Audience claim is missing");
            logger.error(err);
            reject(err);
            return;
        }
        if(!claims[IDCSConstants.TOKEN_CLAIM_EXPIRY]){
            var err = new Error("Expiry claim is missing");
            logger.error(err);
            reject(err);
            return;
        }
        if(!claims[IDCSConstants.TOKEN_CLAIM_ISSUE_AT]){
            var err = new Error("Issue At claim is missing");
            logger.error(err);
            reject(err);
            return;
        }
        if(!claims[IDCSConstants.TOKEN_CLAIM_ISSUER]){
            var err = new Error("Issuer claim is missing");
            logger.error(err);
            reject(err);
            return;
        }
        if(!headers[IDCSConstants.HEADER_CLAIM_KEY_ID]){
            if(!headers[IDCSConstants.HEADER_CLAIM_X5_THUMB]){
                var err = new Error("No kid or x5t present in header");
                logger.error(err);
                reject(err);
                return;
            }
        }
        if (!alg) {
            alg = 'RS256';
        }

        try {
            jwt.sign(claims, privateKey, {algorithm : alg, keyid: headers.kid}, function(err,token){
                if(err){
                    logger.error("generate assertion, error "+ err);
                    reject(err);
                }else {
                    resolve(token);
                }
            });
        }catch(err){
            logger.error("generate assertion, error "+ err);
            reject(err);
        }
    });
};

/**
 * This method verifies id Token given and parse it and return JSON with Id Token claims
 * @param idToken idToken of User
 * @returns {Promise} decoded Id token as a JSON Object
 */
IdcsAuthenticationManager.prototype.validateIdToken = function (idToken) {
    logger.trace("validateIdToken, idToken: "+ idToken);
    var tokenManager  = this.tokenManager;
    var userAssert = this.userAssert;
    return new Promise(function(resolve, reject) {
        tokenManager.verifyIdToken(idToken).then(function (token) {
            userAssert.assertClaims(token).then(function (res) {
                resolve(res);
            }).catch(function (reason) {
                logger.error("validateIdToken, error "+ reason);
                reject(reason);
            });
        }).catch(function (err) {
            logger.error("validateIdToken, error "+ err);
            reject(err);
        })
    });
};

/**
 * This method verifies accessToken given and parse it and return JSON with AccessToken claims
 * @param accessToken accessToken
 * @returns {Promise} decoded Access token as a JSON Object
 */
IdcsAuthenticationManager.prototype.validateAccessToken = function (accessToken) {
    logger.trace("validateAccessToken, accessToken: "+ accessToken);
    var tokenManager  = this.tokenManager;
    var userAssert = this.userAssert;
    return new Promise(function(resolve, reject) {
        tokenManager.verifyAccessToken(accessToken).then(function (token) {
            userAssert.assertClaims(token).then(function (res) {
                resolve(res);
            }).catch(function (reason) {
                logger.error("validateAccessToken, error "+ reason);
                reject(reason);
            });
        }).catch(function (err) {
            logger.error("validateAccessToken, error "+ err);
            reject(err);
        })
    });
};

module.exports = IdcsAuthenticationManager;