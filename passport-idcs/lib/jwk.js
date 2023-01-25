/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

const IDCSConstants = require('./idcsconstants');


function Jwk(jwk){
    this.jwk = jwk;
    this.expiry = new Date().getTime() + IDCSConstants.META_DATA_CACHE_TTL_DEFAULT*1000;
}

Jwk.prototype.getExpiry = function(){
    return this.expiry;
};

Jwk.prototype.getJwk = function(){
    return this.jwk;
};

module.exports = Jwk;


