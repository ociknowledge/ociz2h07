/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

const request = require('request');
const Promise = require('promise');
const querystring = require('querystring');
const util = require('util');
const IDCSConstants = require('./idcsconstants');
const Metadata = require('./metadata.js');
const Logger = require('./logger');


var logger;
var metadata = {};

function IdcsMetadataManager(options, tenantName){
    logger = Logger.getLogger('IdcsMetadataManager');
    this.options = options;
    if(tenantName) {
        this.tenantName = tenantName;
    }else{
        this.tenantName = options[IDCSConstants.CLIENT_TENANT];
    }
}

IdcsMetadataManager.prototype.getMetadata = function() {
    logger.trace("getMetadata");
    var options = this.options;
    var tenantName = this.tenantName;
    return new Promise(function (resolve, reject) {
        if (metadata.hasOwnProperty(tenantName)) {
            var md = metadata[tenantName];
            if(md.getExpiry() > new Date().getTime()) {
                logger.trace("returning metadata  = "+ md.getMetadata());
                resolve(md.getMetadata());
                return;
            }
        }

        var url = getBaseUrl(options, tenantName);
        logger.trace("sending request for url "+ url );
        request({
            url: url
        }, function (err, res, body)  {
            if (!err && res.statusCode == 200) {
                logger.trace("got response  = "+body);
                var jsonObj = JSON.parse(body);
                //this.logger.trace(`getMetadata, jsonObj: ${JSON.stringify(jsonObj)}`);
                metadata[tenantName] = new Metadata(jsonObj);
                if(jsonObj.hasOwnProperty('openid-configuration') && !jsonObj['openid-configuration'].issuer){
                    jsonObj['openid-configuration'].issuer = options.TokenIssuer;
                }
                resolve(jsonObj);
            } else {
                if (err) {
                    logger.error("getMetadata, error: " + err);
                    reject(err);
                } else {
                    logger.error("getMetadata, error: " + body);
                    reject(new Error(body));
                }
            }
        });
    });
}

function getBaseUrl(options, tenantName){
    logger.trace("getBaseUrl");
    var url = options[IDCSConstants.IDCSHost] + IDCSConstants.DISCOVERY_PATH;
    url = url.replace('%tenant%', tenantName);
    return url;
}

module.exports = IdcsMetadataManager;
