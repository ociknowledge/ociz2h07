/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

const jwkToPem = require('jwk-to-pem');
const jwt = require('jsonwebtoken');
const Promise = require('promise');
const url = require('url');
const querystring = require('querystring');
const util = require('util');
const IDCSConstants = require('./idcsconstants');
const IdcsKeyManager = require('./idcskeymanager');
const IdcsAccessTokenManager = require('./idcsaccesstokenmanager');
const LRU = require('lru-cache');
const request = require('request');
const Logger = require('./logger');

var logger;

function IdcsTokenVerifier (options, cacheManager) {
    logger = Logger.getLogger('IdcsTokenVerifier');
    this.options = options;
    if(cacheManager) {
        this.scopeCache = cacheManager.getScopeCache();
    }else {
        logger.trace("IdcsTokenVerifier, constructer didnt initialize cacheManager")
    }
};

IdcsTokenVerifier.prototype.decodeToken = function(token) {
    logger.trace("decodeToken, token: "+ token);
    var tokenDecoded = jwt.decode(token, {
        complete: true
    });
    return tokenDecoded;
};

IdcsTokenVerifier.prototype.verifyJwtToken = function(token) {
    logger.trace("verifyJwtToken, token: "+ token);
    var options = this.options;
    var tv = this;
    var level = options[IDCSConstants.TOKEN_VALIDATION_LEVEL] ? options[IDCSConstants.TOKEN_VALIDATION_LEVEL] : IDCSConstants.VALIDATION_LEVEL_FULL;
    return new Promise(function(resolve, reject){
        var tokenDecoded = tv.decodeToken(token);
        if (!tokenDecoded) {
            var err = new Error('failed to decode Token');
            logger.error(err);
            reject(err);
            return;
        }

        var type = tokenDecoded.payload[IDCSConstants.TOKEN_CLAIM_TOKEN_TYPE];
        var isIdToken = type == 'AT' ? false : true;
        var tenant = getTenantNameFromClaims(options, isIdToken, tokenDecoded.payload);
        if(options[IDCSConstants.CROSS_TENANT]) {
            if (!tenant.match("idcs-[(a-z)|(0-9)]{32}")) {
                var err = new Error("tenant present is token doesnot comply with idcs standards");
                logger.error(err);
                reject(err);
                return;
            }
        }else {
            if(options[IDCSConstants.CLIENT_TENANT] !== tenant){
                var err = new Error("tenant present in token doesn't match with already configured tenant");
                logger.error(err);
                reject(err);
                return;
            }
        }


        var km = new IdcsKeyManager(options, tenant);
        km.getPublicKey()
            .then(function(jwk){
                // get kid used to sign the token
                var kid = tokenDecoded.header.kid;
                var keys = jwk.keys;
                var key;
                if (kid) {
                    key = keys.find((n) => n.kid = kid);
                }

                if(!key){
                    key = keys[0];
                }

                var pem = jwkToPem(key);
                var result;
                try{
                    if(IDCSConstants.VALIDATION_LEVEL_NONE == level){
                        result = tokenDecoded;
                    }else {
                        var skew = IDCSConstants.TOKEN_CLOCK_SKEW_DEFAULT_VALUE;
                        if (options[IDCSConstants.TOKEN_CLOCK_SKEW]) {
                            skew = options[IDCSConstants.TOKEN_CLOCK_SKEW];
                        }
                        var verifyClaims = {
                            clockTolerance: skew,
                            issuer: options[IDCSConstants.TOKEN_ISSUER],
                            algorithms: [key.alg]
                        };
                        result = jwt.verify(token, pem, verifyClaims);
                        var d = new Date();
                        if ((result[IDCSConstants.TOKEN_CLAIM_EXPIRY] + skew) <= d.getTime() / 1000) {
                            var err = new Error("Token is Expired");
                            logger.error(err);
                            reject(err);
                            return;
                        }
                    }
                    logger.trace("verifyJwtToken, returning result  = "+result);
                    resolve(result);
                    return;
                }catch(err){
                    logger.error(err);
                    reject(err);
                    return;
                }
            }).catch(function(err){
                logger.error(err);
                reject(err);
                return;
            })
    });
};

IdcsTokenVerifier.prototype.validateAudience = function(token, isIdToken){
    logger.trace("validateAudience, token: "+ token +", isIdToken: ",isIdToken);
    var options = this.options;
    var tv = this;
    return new Promise(function(resolve, reject){
        if(!token.hasOwnProperty(IDCSConstants.TOKEN_CLAIM_AUDIENCE)){
            if(!token.hasOwnProperty(IDCSConstants.TOKEN_CLAIM_SCOPE)){
                logger.error("token claim scope is missing. validate Audience failed");
                resolve(false);
            }else{
                if(token[IDCSConstants.TOKEN_CLAIM_SCOPE].trim()==''){
                    logger.error("token claim scope is empty. validate Audience failed");
                    resolve(false);
                    return;
                }else{
                    logger.trace("returning validate Audience true");
                    resolve(true);
                    return;
                }
            }
        }else{
            var aud = token[IDCSConstants.TOKEN_CLAIM_AUDIENCE];
            if(!(aud instanceof Array)){
                aud = [aud];
            }
            var necessary = tv.getNecessaryAudience(aud);
            if(necessary.length>0){
                tv.validateNecessaryAudience(token, necessary).then(function(ret){
                    logger.trace("returning validate Necessary Audience with result = "+ret);
                    resolve(ret);
                    return;
                }).catch(function(err){
                    logger.error(err);
                    reject(err);
                    return;
                });
            }else{
                tv.validateSufficientAudience(token, aud, isIdToken).then(function(ret){
                    logger.trace("returning validate Sufficient Audience with result = "+ret);
                    resolve(ret);
                    return;
                }).catch(function(err){
                    logger.error(err);
                    reject(err);
                    return;
                });
            }
        }
    });
};

IdcsTokenVerifier.prototype.getNecessaryAudience = function(aud){
    logger.trace("getNecessaryAudience, aud: "+ aud);
    var necessary  = [];
    for(var i=0; i<aud.length; i++){
        var audience = aud[i];
        if(audience.startsWith(IDCSConstants.NECESSARY_AUDIENCE_PREFIX)){
            necessary.push(audience);
        }
    }
    logger.trace("returning getNecessaryAudience with val = "+necessary);
    return necessary;
};

IdcsTokenVerifier.prototype.validateNecessaryAudience = function(token, necessary){
    logger.trace("validateNecessaryAudience, token: "+ token +", necessary: "+necessary);
    var tv = this;
    return new Promise(function(resolve, reject){
        var validations = [];
        for(var i=0; i<necessary.length; i++){
            var audience = necessary[i];
            validations.push(tv.__validateNecessaryAudience(token, audience));
        }
        Promise.all(validations).then(function(values){
            for(var j=0; j<values.length; j++){
                var value = values[j];
                if(value==false){
                    logger.error("validateNecessaryAudience, return false");
                    resolve(false);
                    return;
                }
            }
            logger.trace("validateNecessaryAudience, return true");
            resolve(true);
            return;
        }).catch(function(err){
            logger.error(err);
            reject(err);
            return;
        });
    });
};

IdcsTokenVerifier.prototype.__validateNecessaryAudience = function(token, audience){
    logger.trace("__validateNecessaryAudience, token: "+ token +", audience: "+audience);
    var tv = this;
    return new Promise(function(resolve, reject){
        if(audience==IDCSConstants.AUDIENCE_SCOPE_ACCOUNT){
            tv.__validateScopeAccount(token).then(function(ret){
                logger.trace("__validateNecessaryAudience, returning = "+ret);
                resolve(ret);
                return;
            }).catch(function(err){
                logger.error(err);
                reject(err);
                return;
            })
        }else if(audience.startsWith(IDCSConstants.AUDIENCE_SCOPE_TAG)){
            tv.__validateScopeTag(audience).then(function(ret){
                logger.trace("__validateNecessaryAudience, returning = "+ret);
                resolve(ret);
                return;
            }).catch(function(err){
                logger.error(err);
                reject(err);
                return;
            });
        }else{
            logger.error("__validateNecessaryAudience, returning = false");
            resolve(false);
            return;
        }
    });
};

IdcsTokenVerifier.prototype.__validateScopeAccount = function(token){
    logger.trace("__validateScopeAccount, token: "+ token);
    var options = this.options;
    return new Promise(function(resolve, reject){
        var client_tenant = token[IDCSConstants.TOKEN_CLAIM_TENANT];
        if(!options[IDCSConstants.CROSS_TENANT]  && client_tenant!=options[IDCSConstants.CLIENT_TENANT]){
            logger.error("__validateScopeAccount, returning false");
            resolve(false);
        }else{
            logger.trace("__validateScopeAccount, returning true");
            resolve(true);
        }
    });
};

IdcsTokenVerifier.prototype.__validateScopeTag = function(audience){
    logger.trace("__validateScopeTag , audience: "+ audience );
    var tv = this;
    var options = this.options;
    return new Promise(function(resolve, reject){
        tv.getTokenTags(audience).then(function(tokenTags){
            if(options[IDCSConstants.FULLY_QUALIFIED_SCOPES]){
                var scopes = options[IDCSConstants.FULLY_QUALIFIED_SCOPES].split(",");
                var tags = [];
                for(var i=0; i<scopes.length; i++) {
                    var scope = scopes[i];
                    tags.push(tv.getTagsForResource(scope));
                }
                Promise.all(tags).then(function(values){
                    for(var j=0; j<values.length; j++){
                        var resourceTags = values[j];
                        for (var tag in resourceTags){
                            if(tokenTags.hasOwnProperty(tag)) {
                                logger.trace("__validateScopeTag returning true");
                                resolve(true);
                                return;
                            }
                        }
                    }
                    logger.error("__validateScopeTag returning false");
                    resolve(false);
                    return;
                });
            }else{
                var err = new Error("FullyQualifiedScopes missing in Options");
                logger.error(err);
                reject(err)
                return;
            }
        }).catch(function(err){
            logger.error(err);
            reject(err);
            return;
        })
    });
};

IdcsTokenVerifier.prototype.getTokenTags = function(audience){
    logger.trace("getTokenTags, audience: "+ audience);
    return new Promise(function(resolve, reject){
        var tokenTags = {};
        var i = audience.indexOf("=");
        var decoded = Buffer.from(audience.substring(i+1), 'base64').toString("ascii");
        var parsed = JSON.parse(decoded);
        if(parsed["tags"]){
            var tags = parsed["tags"];
            for(var j=0; j<tags.length; j++){
                var tag = tags[j];
                tokenTags[tag["key"] + ":" + tag["value"]] = "";
            }
        }
        logger.trace("getTokenTags, returning: "+ tokenTags);
        resolve(tokenTags);
    });

};

IdcsTokenVerifier.prototype.getTagsForResource = function(scope){
    logger.trace("getTagsForResource,  , scope: "+ scope );
    var key = scope;
    var options = this.options;
    var resourceTags = {};
    var scopeCache = this.scopeCache;
    return new Promise(function(resolve, reject) {
        if (scopeCache) {
            var ret = scopeCache.get(key);
            if (ret) {
                logger.trace("getTagsForResource returning:",ret);
                resolve(ret);
                return;
            }
        }
        var atm = new IdcsAccessTokenManager(options);
        atm.getAccessToken().then(function(at){
            var url = getBaseUrl(options);
            url+=IDCSConstants.GET_APP_INFO_PATH;
            url+=util.format(IDCSConstants.FQS_FILTER, "\"" + scope + "\"");
            var headers = {};
            headers[IDCSConstants.HEADER_AUTHORIZATION] =  util.format(IDCSConstants.AUTH_BEARER, at);
            logger.trace("sending request for url "+ url + " with headers = "+ JSON.stringify(headers));
            request({
                url: url,
                headers : headers
            }, function (err, res, body) {
                if (!err && res.statusCode == 200) {
                    logger.trace("response = "+body);
                    var jsonObj = JSON.parse(body);
                    var resources = jsonObj["Resources"];
                    for(var i=0; i<resources.length; i++){
                        var resource = resources[i];
                        if(resource["tags"]){
                            var tags = resource["tags"];
                            for(var j=0; j<tags.length; j++){
                                var tag = tags[j];
                                var resKey = tag["key"] + ":" + tag["value"];
                                resourceTags[resKey] = "";
                            }
                        }
                    }
                    //this.logger.trace(`getUser, jsonObj: ${JSON.stringify(jsonObj)}`);
                    if(scopeCache) {
                        scopeCache.set(key, resourceTags);
                    }
                    resolve(resourceTags);
                    return;
                } else {
                    if (err) {
                        logger.error("tokenverifier, error: "+err);
                        reject(err);
                        return;
                    } else {
                        logger.error("tokenverifier, error: "+body);
                        reject(new Error(body));
                    }
                }
            });

        }).catch(function(err){
            logger.error(err);
            reject(err);
        });
    });
};

IdcsTokenVerifier.prototype.validateSufficientAudience = function (token, aud, idToken){
    logger.trace("validateSufficientAudience, aud: "+ aud + ", idToken: "+idToken);
    var options = this.options;
    var tv = this;
    return new Promise(function(resolve, reject){
        // if Idtoken is true and cross tenant is true then
        // dont need to check sufficient audience
        // Note: need to check with oauth team
        if(options[IDCSConstants.CROSS_TENANT] && idToken){
            logger.trace("validateSufficientAudience for idToken and cross tenant case returning true");
            resolve(true);
            return;
        }
        var i;
        for(i=0; i<aud.length; i++){
            var audience = aud[i];
            if(idToken){
                if(audience == options[IDCSConstants.CLIENT_ID]){
                    logger.trace("validateSufficientAudience returning true");
                    resolve(true);
                    return;
                }
            }else{
                var resourceTenant =  getTenantNameFromClaims(options, idToken, token);
                if(tv.__validateSufficientAudience(url.parse(audience), url.parse(options[IDCSConstants.AUDIENCE_SERVICE_URL]), resourceTenant, options[IDCSConstants.CROSS_TENANT])){
                    logger.trace("validateSufficientAudience returning true");
                    resolve(true);
                    return;
                }
            }
        }
        logger.error("validateSufficientAudience returning false");
        resolve(false);
        return;
    });
};

IdcsTokenVerifier.prototype.__validateSufficientAudience = function(audienceUrl, serviceUrl, resourceTenancy, crossTenant){
    logger.trace("__validateSufficientAudience, audienceUrl: "+ audienceUrl + ", serviceUrl: "+serviceUrl + ", resourceTenancy: "+resourceTenancy+ ", crossTenant: "+crossTenant);
    if(audienceUrl.protocol != serviceUrl.protocol){
        return false;
    }

    var host = serviceUrl.hostname;
    if(crossTenant){
        var idx = host.indexOf('.');
        host = resourceTenancy + host.substr(idx);
    }

    if(host != audienceUrl.hostname){
        return false;
    }

    var audPort, servicePort;


    if(audienceUrl.port === null){
        if(audienceUrl.protocol === 'https:'){
            audPort = '443';
        }else{
            audPort = '80';
        }
    } else {
        audPort = audienceUrl.port;
    }

    if(serviceUrl.port === null){
        if(serviceUrl.protocol === 'https:'){
            servicePort = '443';
        }else{
            servicePort = '80';
        }
    } else {
        servicePort = serviceUrl.port;
    }

    if(audPort !== servicePort){
        return false;
    }

    if(audienceUrl.pathname){
        if(!serviceUrl.pathname.startsWith(audienceUrl.pathname))
            return false;
    }
    return true;

};

function getBaseUrl(options){
    logger.trace("getBaseUrl, options: "+ options);
    var url = options[IDCSConstants.IDCSHost];
    url = url.replace('%tenant%', options[IDCSConstants.CLIENT_TENANT]);
    return url;
}


function getTenantNameFromClaims(options, isIdToken, tokenDecoded) {
    var tenant;
    if (isIdToken) {
        tenant = tokenDecoded[options[IDCSConstants.USER_TENANT_TOKEN_CLAIM] ? options[IDCSConstants.USER_TENANT_TOKEN_CLAIM] : IDCSConstants.TOKEN_CLAIM_USER_TENANT];
    } else {
        tenant = tokenDecoded[options[IDCSConstants.CLIENT_TENANT_TOK_CLAIM] ? options[IDCSConstants.CLIENT_TENANT_TOK_CLAIM] : IDCSConstants.TOKEN_CLAIM_CLIENT_TENANT];
    }
    return tenant;
}

module.exports = IdcsTokenVerifier;
