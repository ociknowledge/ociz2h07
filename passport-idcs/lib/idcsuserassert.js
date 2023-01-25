/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

const IDCSConstants = require('./idcsconstants');
const CONSTANTS = require('./constants');
const IdcsMetadataManager = require('./idcsmetadatamanager');
const IdcsAccessTokenManager = require('./idcsaccesstokenmanager');
const util = require('util');
const request = require('request');
const Promise = require('promise');
const Logger = require('./logger');

var logger;

function IdcsUserAssert(options, cacheManager){
    logger = Logger.getLogger('IdcsTokenManager');
    this.options = options;
    if(cacheManager) {
        this.asserterCache = cacheManager.getAsserterCache();
    } else{
        logger.trace("IdcsUserAssert,  constructor didn't initialize cacheManager");
    }
}

/**
 * This method asserts the identity with App Roles and Group Memberships for a given token
 * @param jwt json web token
 * @returns {Promise} when fulfilled returns a JSON Object with asserted Attributes else return Error
 */
IdcsUserAssert.prototype.assertClaims = function (jwt) {
    logger.trace("assertClaims, jwt: "+ JSON.stringify(jwt));
    var options = this.options;
    var asserterCache = this.asserterCache;
    var ret={};
    return new Promise(function(resolve, reject) {
        ret.token = jwt;
        var id;
        var tenant;
        var subType;
        var userIdFromClaim = jwt[options[IDCSConstants.USER_ID_TOK_CLAIM] ? options[IDCSConstants.USER_ID_TOK_CLAIM] : IDCSConstants.TOKEN_CLAIM_USER_ID];
        if('AT'==jwt[IDCSConstants.TOKEN_CLAIM_TOKEN_TYPE] && !userIdFromClaim){
            id = jwt[options[IDCSConstants.CLIENT_ID_TOK_CLAIM] ? options[IDCSConstants.CLIENT_ID_TOK_CLAIM] : IDCSConstants.TOKEN_CLAIM_CLIENT_ID];
            tenant = jwt[options[IDCSConstants.CLIENT_TENANT_TOK_CLAIM] ? options[IDCSConstants.CLIENT_TENANT_TOK_CLAIM] : IDCSConstants.TOKEN_CLAIM_CLIENT_TENANT];
            subType = jwt[IDCSConstants.TOKEN_CLAIM_SUB_TYPE];
        }else{
            id = userIdFromClaim;
            tenant =jwt[options[IDCSConstants.USER_TENANT_TOKEN_CLAIM] ? options[IDCSConstants.USER_TENANT_TOKEN_CLAIM] : IDCSConstants.TOKEN_CLAIM_USER_TENANT];
            subType = jwt[IDCSConstants.TOKEN_CLAIM_SUB_TYPE];
        }

        var result;

        //This check is required to decorate the response for backward compatibility
        if(userIdFromClaim) {
            result = CONSTANTS.populateAuthenticatedUser(jwt);
        }
        //This check is required to decorate the response for backward compatibility
        if('AT'==jwt[IDCSConstants.TOKEN_CLAIM_TOKEN_TYPE]) {
            result = CONSTANTS.populateClientClaims(result, jwt);
        }

        var key = tenant + ":" + id;
        logger.trace("assertClaims: checking in asserter cache for key = "+key);
        var val = asserterCache.get(key);
        if(val){
            result = CONSTANTS.populateGroupAndRoles(result,val);
            ret.result = result;
            logger.trace("assertClaims: asserter cache hit returning result = "+JSON.stringify(ret));
            resolve(ret);
            return;
        }
        var mdm = new IdcsMetadataManager(options, tenant);
        mdm.getMetadata().then(function(md){
            var url = md[IDCSConstants.META_ACCESS_CONFIGURATION][IDCSConstants.META_ACCESS_CONFIGURATION_ASSERTER_ENDPOINT];
            var atm = new IdcsAccessTokenManager(options, tenant);
            atm.getAccessToken().then(function(at){
                var payload = {};
                if(options[IDCSConstants.APP_NAME]){
                    payload[IDCSConstants.IDCS_APPNAME_FILTER_ATTRIB] = options[IDCSConstants.APP_NAME];
                }
                // This check is that if subtype is null then goto whatever going on previously otherwise check for subtype
                if (id.endsWith("_APPID") || (subType && subType === "client")) {
                    // do nothing
                } else{
                    payload[IDCSConstants.IDCS_MAPPING_ATTRIBUTE] = options[IDCSConstants.USER_ID_RES_ATTR] ? options[IDCSConstants.USER_ID_RES_ATTR] : IDCSConstants.MAPPING_ATTR_ID;
                }
                payload[IDCSConstants.IDCS_MAPPING_ATTRIBUTE_VALUE] = id ;
                var schemas = [IDCSConstants.IDCS_ASSERTER_SCHEMA];
                payload[IDCSConstants.IDCS_SCHEMAS] = schemas;
                payload[IDCSConstants.IDCS_INCLUDE_MEMBERSHIPS] = true;
                var headers = {};
                headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BEARER, at);
                headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.APPLICATION_JSON;
                if(subType && subType === "client") {
                    payload[IDCSConstants.SUBJECT_TYPE_ATTR]  =  subType;
                }

                var body = JSON.stringify(payload);
                logger.trace("assertClaims, sending request for url "+ url + " with headers = "+ JSON.stringify(headers)+ " and body  = "+ body);
                request.post({
                    url: url,
                    headers : headers,
                    body : body
                }, function(err, res, body) {
                    if (!err && (res.statusCode == 200 || res.statusCode == 201)) {
                        logger.trace("assertClaims , response  = "+body);
                        var jsonObj = JSON.parse(body);
                        asserterCache.set(key, jsonObj);
                        logger.trace("assertClaims , putting key  = "+key +", and value = "+ JSON.stringify(jsonObj));
                        result = CONSTANTS.populateGroupAndRoles(result,jsonObj);
                        ret.result = result;
                        resolve(ret);
                        return;
                    } else {
                        if (err) {
                            logger.error("assertClaims, error: "+err);
                            reject(err);
                            return;
                        } else {
                            logger.error("assertClaims, error: "+body);
                            reject(new Error(body));
                            return;
                        }
                    }
                });
            }).catch(function(err){
                logger.error("assertClaims, error: "+err);
                reject(err);
            });
        }).catch(function(err){
            logger.error("assertClaims, error: "+err);
            reject(err);
        });
    });
};



module.exports = IdcsUserAssert;

