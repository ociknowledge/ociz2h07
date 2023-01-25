/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

const IDCSConstants = require('./idcsconstants');

function Metadata(md){
    this.md = md;
    this.expiry = new Date().getTime() + IDCSConstants.META_DATA_CACHE_TTL_DEFAULT*1000;
}

Metadata.prototype.getExpiry = function(){
    return this.expiry;
};

Metadata.prototype.getMetadata = function(){
    return this.md;
};

module.exports = Metadata;


