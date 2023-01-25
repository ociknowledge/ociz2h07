/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

const request = require('request');
const Promise = require('promise');
const querystring = require('querystring');
const util = require('util');
const IDCSConstants = require('./idcsconstants');
const IdcsMetadataManager = require('./idcsmetadatamanager');
const IdcsAccessTokenManager = require('./idcsaccesstokenmanager');
const Jwk = require('./jwk.js');
const Logger = require('./logger');


var logger;
var keys = {};


function IdcsKeyManager(options, tenantName){
    logger = Logger.getLogger('IdcsAuthenticationManager');
    this.options = options;
    this.tenantName = tenantName;
}

IdcsKeyManager.prototype.getPublicKey = function(){
    logger.trace("getPublicKey");
    var options = this.options;
    var tenantName = this.tenantName;
    return new Promise(function(resolve, reject){
        if (keys.hasOwnProperty(tenantName)) {
            var key = keys[tenantName];
            if(key.getExpiry() > new Date().getTime()){
                resolve(key.getJwk());
                return;
            }
        }

        var mdm = new IdcsMetadataManager(options, tenantName);
        mdm.getMetadata()
            .then(function(md){
                var jwkUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_JWKS_URI];
                var atm = new IdcsAccessTokenManager(options);
                atm.getAccessToken(options)
                    .then(function(at){
                        var headers = {};
                        headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BEARER, at);
                        logger.trace("getPublicKey , sending request for url "+ jwkUrl + " with headers = "+ JSON.stringify(headers));
                        request({
                            url: jwkUrl,
                            headers : headers
                        }, function (err, res, body) {
                            if (!err && res.statusCode == 200) {
                                logger.trace("getPublicKey, response = "+ body);
                                var jsonObj = JSON.parse(body);
                                keys[options[IDCSConstants.CLIENT_TENANT]] = new Jwk(jsonObj);
                                resolve(jsonObj);
                            } else {
                                if (err) {
                                    logger.error("getPublicKey, error: "+err);
                                    reject(err)
                                } else {
                                    logger.error("getPublicKey, error: "+ body);
                                    reject(new Error(body));
                                }
                            }
                        });
                    }).catch(function(err){
                        logger.error(err);
                        reject(err);
                    })
            }).catch(function(err){
                logger.error(err);
                reject(err);
            })

    });
};

module.exports = IdcsKeyManager;
