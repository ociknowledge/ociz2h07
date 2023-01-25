/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

const request = require('request');
const Promise = require('promise');
const querystring = require('querystring');
const util = require('util');
const IdcsAuthenticationManager = require('./idcsauthenticationmanager');
const IDCSConstants = require('./idcsconstants');

var tokens = {};

function IdcsAccessTokenManager(options) {
        this.options = options;
}

function getTokenPayload(token){
    var parts = token.split('.');
    var decoded = new Buffer(parts[1], 'base64');
    var ret = JSON.parse(decoded.toString('utf8'));
    return ret;
}

IdcsAccessTokenManager.prototype.getAccessToken = function(){
        var opts =this.options;
        var tenantName = opts[IDCSConstants.CLIENT_TENANT];
        return new Promise(function(resolve,reject){
            if (tokens.hasOwnProperty(tenantName)) {
                var token = tokens[tenantName];
                var payload = getTokenPayload(token);
                var now = (new Date().getTime())/1000;
                if((payload[IDCSConstants.TOKEN_CLAIM_EXPIRY] - 120) > now){
                    resolve(token);
                    return;
                }
            }
            var am = new IdcsAuthenticationManager(opts);
            am.clientCredentials(IDCSConstants.MY_SCOPES)
                .then(function (res) {
                    var token = res[IDCSConstants.ACCESS_TOKEN];
                    tokens[tenantName] = token;
                    resolve(token);
                }).catch(function (err) {
                    reject(err);
                })

        });
    };


module.exports=IdcsAccessTokenManager;