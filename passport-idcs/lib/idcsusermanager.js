/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

const request = require('request');
const Promise = require('promise');
const querystring = require('querystring');
const util = require('util');
const CONSTANTS = require('./constants');
const IDCSConstants = require('./idcsconstants');
const IdcsAccessTokenManager = require('./idcsaccesstokenmanager');
const IdcsMetadataManager = require('./idcsmetadatamanager');
const IdcsTokenManager = require('./idcstokenmanager');
const LRU = require('lru-cache');

var cache = null;
var asserterCache = null;
var evicted;

/**
 * @deprecated
 */
function IdcsUserManager(options) {
    this.options = options;
    if(cache==null){
        var opts = {};
        if(options[IDCSConstants.USER_CACHE_MAX_SIZE]){
            opts["max"] = options[IDCSConstants.USER_CACHE_MAX_SIZE];
        }else{
            opts["max"] = IDCSConstants.USER_CACHE_MAX_SIZE_DEFAULT;
        }

        if(options[IDCSConstants.USER_CACHE_TTL]){
            opts["maxAge"] = options[IDCSConstants.USER_CACHE_TTL] * 1000;
        }else{
            opts["maxAge"] = IDCSConstants.USER_CACHE_TTL_DEFAULT * 1000;
        }

        cache = new LRU(opts);

        asserterCache = new LRU(opts);
    }

}

/**
 * This method fetches the User details for the given user Id
 * @param id the Id of user
 * @returns {Promise} when fulfilled returns A User Object containing User Detail attributes else returns error
 * @deprecated
 */
IdcsUserManager.prototype.getUser = function (userId){
    var options = this.options;
    return new Promise(function(resolve, reject){
        if(!userId || userId==''){
            reject(new Error("User Id is Empty"));
            return;
        }
        var ret = cache.get(options[IDCSConstants.CLIENT_TENANT] + ":" + userId);
        if(ret){
            resolve(ret);
            return;
        }
        var atm = new IdcsAccessTokenManager(options);
        atm.getAccessToken()
            .then(function(access_token){
                var url = getBaseUrl(options);
                url+= util.format(IDCSConstants.GET_USER_URL, userId);
                var params = {};
                params[IDCSConstants.PARAM_ATTRIBUTES] = IDCSConstants.USER_ATTRUBUTES;
                url+= "?" + querystring.stringify(params);
                var headers = {};
                headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BEARER, access_token);
                request({
                    url: url,
                    headers : headers
                }, function (err, res, body) {
                    if (!err && res.statusCode == 200) {
                        var jsonObj = JSON.parse(body);
                        //this.logger.trace(`getUser, jsonObj: ${JSON.stringify(jsonObj)}`);
                        cache.set(options[IDCSConstants.CLIENT_TENANT] + ":" + userId, jsonObj);
                        resolve(jsonObj);
                    } else {
                        if (err) {
                            //this.logger.error(`getUser, error: ${err}`);
                            reject(err);
                        } else {
                            //this.logger.error(`getUser, error: ${body}`);
                            reject(new Error(body));
                        }
                    }
                });
            }).catch(function(err){
                reject(err);
            })
    });
}

/**
 * This method fetches the authenticated user to which access token belongs
 * @param access_token Access token of User
 * @returns {Promise} when fulfilled returns A User Object containing User Detail attributes else returns error
 * @deprecated
 */
IdcsUserManager.prototype.getAuthenticatedUser = function (access_token){
    var options = this.options;
    return new Promise(function(resolve, reject){
        if(!access_token || access_token==''){
            reject(new Error("Access Token is Empty"));
            return;
        }
        var tm = new IdcsTokenManager(options);
        tm.verifyAccessToken(access_token)
            .then(function(at){
                var ret = cache.get(options[IDCSConstants.CLIENT_TENANT] + ":" + at[IDCSConstants.TOKEN_CLAIM_SUBJECT]);
                if(ret){
                    resolve(ret);
                    return;
                }
                var url = getBaseUrl(options);
                url+= IDCSConstants.GET_ME_URL;
                var params = {};
                params[IDCSConstants.PARAM_ATTRIBUTES] = IDCSConstants.USER_ATTRUBUTES;
                url+= "?" + querystring.stringify(params);
                var headers = {};
                headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BEARER, access_token);
                request({
                    url: url,
                    headers : headers
                }, function(err, res, body) {
                    if (!err && res.statusCode == 200) {
                        var jsonObj = JSON.parse(body);
                        //this.logger.trace(`getUser, jsonObj: ${JSON.stringify(jsonObj)}`);
                        cache.set(options[IDCSConstants.CLIENT_TENANT] + ":" + at[IDCSConstants.TOKEN_CLAIM_SUBJECT], jsonObj);
                        resolve(jsonObj);
                    } else {
                        if (err) {
                            //this.logger.error(`getUser, error: ${err}`);
                            reject(err);
                        } else {
                            //this.logger.error(`getUser, error: ${body}`);
                            reject(new Error(body));
                        }
                    }
                });
            }).catch(function(err){
                reject(err);
            });
    });
}

/**
 * @deprecated
 */
IdcsUserManager.prototype.assertUser = function(mappingAttributeValue, mappingAttributeName){
    var options = this.options;
    return new Promise(function(resolve, reject){
        var key = mappingAttributeValue + ":" + options[IDCSConstants.CLIENT_TENANT];
        var ret = asserterCache.get(key);
        if(ret){
            resolve(ret);
            return;
        }
        var mdm = new IdcsMetadataManager(options);
        mdm.getMetadata()
            .then(function(md){
                var url = md[IDCSConstants.META_ACCESS_CONFIGURATION][IDCSConstants.META_ACCESS_CONFIGURATION_ASSERTER_ENDPOINT];
                var atm = new IdcsAccessTokenManager(options);
                atm.getAccessToken()
                    .then(function(at){
                        var body = {};
                        body["mappingAttribute"] =  mappingAttributeName ? mappingAttributeName : "username";
                        body["mappingAttributeValue"] = mappingAttributeValue;
                        body["includeMemberships"] =  true;
                        body["schemas"] = ["urn:ietf:params:scim:schemas:oracle:idcs:Asserter"];
                        var payload = JSON.stringify(body);
                        var headers = {};
                        headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BEARER, at);
                        headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.APPLICATION_JSON;

                        request.post({
                            url: url,
                            headers : headers,
                            body : payload
                        }, function(err, res, body) {
                            if (!err && (res.statusCode == 200 || res.statusCode == 201)) {
                                var jsonObj = JSON.parse(body);
                                //this.logger.trace(`getUser, jsonObj: ${JSON.stringify(jsonObj)}`);
                                asserterCache.set(key, jsonObj);
                                resolve(jsonObj);
                            } else {
                                if (err) {
                                    //this.logger.error(`getUser, error: ${err}`);
                                    reject(err);
                                } else {
                                    //this.logger.error(`getUser, error: ${body}`);
                                    reject(new Error(body));
                                }
                            }
                        });

                    }).catch(function(err){
                        reject(err);
                    })
            }).catch(function(err){
                reject(err);
            });
    });
}

/**
 * This method asserts the identity with App Roles and Group Memberships for a given token
 * @param token Access Token or Id Token
 * @returns {Promise} when fulfilled returns a JSON Object with asserted Attributes else return Error
 * @deprecated
 */
IdcsUserManager.prototype.assertClaims = function(token){
    var options = this.options;
    var ret={};
    return new Promise(function(resolve, reject) {
        var tm = new IdcsTokenManager (options);
        tm.verifyToken(token).then(function(jwt){
            ret.token = jwt;
            var id;
            var tenant;
            if('AT'==jwt[IDCSConstants.TOKEN_CLAIM_TOKEN_TYPE] && !jwt[options[IDCSConstants.USER_ID_TOK_CLAIM] ? options[IDCSConstants.USER_ID_TOK_CLAIM] : IDCSConstants.TOKEN_CLAIM_USER_ID]){
                id = jwt[options[IDCSConstants.CLIENT_ID_TOK_CLAIM] ? options[IDCSConstants.CLIENT_ID_TOK_CLAIM] : IDCSConstants.TOKEN_CLAIM_CLIENT_ID];
                tenant =jwt[options[IDCSConstants.CLIENT_TENANT_TOK_CLAIM] ? options[IDCSConstants.CLIENT_TENANT_TOK_CLAIM] : IDCSConstants.TOKEN_CLAIM_CLIENT_TENANT];
                if(!id.endsWith("_APPID")){
                    ret.result = CONSTANTS.populateClientClaims(null, jwt);
                    resolve(ret);
                    return;
                }
            }else{
                id = jwt[options[IDCSConstants.USER_ID_TOK_CLAIM] ? options[IDCSConstants.USER_ID_TOK_CLAIM] : IDCSConstants.TOKEN_CLAIM_USER_ID];
                tenant =jwt[options[IDCSConstants.USER_TENANT_TOKEN_CLAIM] ? options[IDCSConstants.USER_TENANT_TOKEN_CLAIM] : IDCSConstants.TOKEN_CLAIM_USER_TENANT];
            }

            var result;
            if(jwt[options[IDCSConstants.USER_ID_TOK_CLAIM] ? options[IDCSConstants.USER_ID_TOK_CLAIM] : IDCSConstants.TOKEN_CLAIM_USER_ID]) {
                result = CONSTANTS.populateAuthenticatedUser(jwt);
            }
            if('AT'==jwt[IDCSConstants.TOKEN_CLAIM_TOKEN_TYPE]) {
                result = CONSTANTS.populateClientClaims(result, jwt);
            }

            if(!options[IDCSConstants.ONLY_USER_TOK_CLAIM_ENABLED]){
                if(jwt[options[IDCSConstants.GROUP_TOKEN_CLAIM] ? options[IDCSConstants.GROUP_TOKEN_CLAIM] : IDCSConstants.TOKEN_CLAIM_GROUPS]
                || jwt[options[IDCSConstants.APP_ROLE_TOKEN_CLAIM] ? options[IDCSConstants.APP_ROLE_TOKEN_CLAIM] : IDCSConstants.TOKEN_CLAIM_APP_ROLES]){
                    ret.result = result;
                    resolve(ret);
                    return;
                }
            }

            var key = tenant + ":" + id;
            var val = asserterCache.get(key);
            if(val){
                result = CONSTANTS.populateGroupAndRoles(result,val);
                ret.result = result;
                resolve(ret);
                return;
            }

            var mdm = new IdcsMetadataManager(options);
            mdm.getMetadata().then(function(md){
                var url = md[IDCSConstants.META_ACCESS_CONFIGURATION][IDCSConstants.META_ACCESS_CONFIGURATION_ASSERTER_ENDPOINT];

                var atm = new IdcsAccessTokenManager(options);
                atm.getAccessToken().then(function(at){
                    var payload = {};
                    if(options[IDCSConstants.APP_NAME]){
                        payload[IDCSConstants.IDCS_APPNAME_FILTER_ATTRIB] = options[IDCSConstants.APP_NAME];
                    }
                    if(!id.endsWith("_APPID")){
                        payload[IDCSConstants.IDCS_MAPPING_ATTRIBUTE] = options[IDCSConstants.USER_ID_RES_ATTR] ? options[IDCSConstants.USER_ID_RES_ATTR] : IDCSConstants.MAPPING_ATTR_ID;
                    }
                    payload[IDCSConstants.IDCS_MAPPING_ATTRIBUTE_VALUE] = id ;
                    var schemas = [IDCSConstants.IDCS_ASSERTER_SCHEMA];
                    payload[IDCSConstants.IDCS_SCHEMAS] = schemas;
                    payload[IDCSConstants.IDCS_INCLUDE_MEMBERSHIPS] = true;

                    var headers = {};
                    headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BEARER, at);
                    headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.APPLICATION_JSON;
                    var body = JSON.stringify(payload);

                    request.post({
                        url: url,
                        headers : headers,
                        body : body
                    }, function(err, res, body) {
                        if (!err && (res.statusCode == 200 || res.statusCode == 201)) {
                            var jsonObj = JSON.parse(body);
                            asserterCache.set(key, jsonObj);
                            //this.logger.trace(`getUser, jsonObj: ${JSON.stringify(jsonObj)}`);
                            result = CONSTANTS.populateGroupAndRoles(result,jsonObj);
                            ret.result = result;
                            resolve(ret);
                        } else {
                            if (err) {
                                //this.logger.error(`getUser, error: ${err}`);
                                reject(err);
                            } else {
                                //this.logger.error(`getUser, error: ${body}`);
                                reject(new Error(body));
                            }
                        }
                    });
                }).catch(function(err){

                });
            }).catch(function(err){

            });
        }).catch(function(err){
            reject(err);
        })
    });
}

/**
 *
 * @param options
 * @returns {string | void | *}
 * @deprecated
 */
function getBaseUrl(options){
    var url = options[IDCSConstants.IDCSHost];
    url = url.replace('%tenant%', options[IDCSConstants.CLIENT_TENANT]);
    return url;
}

module.exports = IdcsUserManager;

