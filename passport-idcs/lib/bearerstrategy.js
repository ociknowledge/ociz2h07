/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

/*
DESCRIPTION
IDCS server's passport bearer authentication strategy.

MODIFIED    (MM/DD/YY)
junyhe      01/04/17 - Creation
 */
'use strict';

// core module
const passport = require('passport');

// project module
const Logger = require('./logger');
const CONSTANTS = require('./constants');
const IdcsAuthenticationManager = require('./idcsauthenticationmanager');
const UserManager = require('./idcsusermanager');

// bearer token header name
const BEARER_TOKEN_HEADER_KEY = 'authorization';

// resource tenant header name
const RESOURCE_TENANT_HEADER_KEY = 'x-resource-identity-domain-name';

class BearerStrategy extends passport.Strategy {
	/**
	 * Constructor for bearer access token assertion strategy
	 *  @param {Object}       options Configurations for idcs bearer strategy.
	 * - IDCSHost             Required, IDCS host address. e.g. https://%tenant%.idcspool0.identity.c9dev0.oraclecorp.com
	 * - ClientTenant         Required, OAuth client tenant
	 * - ClientId             Required, OAuth client id
	 * - ClientSecret         Required, OAuth client secret
	 * - AudienceServiceUrl   Required, for token validation
     * - TokenIssuer          Required, for token validation
     * - CrossTenant          Optional, set true for Cross tenant use cases
	 * - TokenClockSkew     Optional, number of seconds to tolerate when checking the nbf and exp claims, to deal with small clock differences among different servers, default: 120
	 * - LogLevel             Optional, set logging level, default level: warn
	 * @param {Function} verify
	 * @access public
	 * @constructor
	 */
	constructor(options, verify) {
		super();

		// verify configurations
		this.options = CONSTANTS.validateOptions(options);
		this.name = 'Bearer';
		this.verify = verify;

		Logger.setLevel(this.options[CONSTANTS.LOG_LEVEL]);
		this.logger = Logger.getLogger('Bearer');
		this.logger.trace("BearerStrategy, constructor, options: " + options + ", options after handling: "+this.options);
		var verifyClaims = {
			clockTolerance: this.options[CONSTANTS.TOKEN_CLOCK_SKEW]
		};
		if (this.options[CONSTANTS.TOKEN_CLAIM_ISSUER]) {
			verifyClaims.issuer = this.options[CONSTANTS.TOKEN_CLAIM_ISSUER];
		}
		this.am  = new  IdcsAuthenticationManager(this.options);
	}

	/**
	 * Authenticate request.
	 *
	 * @param {Object} req The request to authenticate.
	 * @param {Object} options Strategy-specific options.
	 * @api public
	 */
	authenticate(req, options) {
		var logger = this.logger;
		logger.trace("BearerStrategy, authenticate, headers: "+ JSON.stringify(req.headers) +", options: "+ options);
		var at = null;
		// get token from headers
		logger.trace("req.headers[BEARER_TOKEN_HEADER_KEY]: "+ JSON.stringify(req.headers[BEARER_TOKEN_HEADER_KEY]));
		if (req.headers[BEARER_TOKEN_HEADER_KEY]) {
			var atValues = req.headers[BEARER_TOKEN_HEADER_KEY].split(' ');
			if (atValues.length == 2 && atValues[0].toLowerCase() === 'bearer') {
				at = atValues[1];
			}
		}

		if (!at) {
			var err = "missing token in the header["+ BEARER_TOKEN_HEADER_KEY +"] or body.token";
            logger.error(err);
			return this.fail(err);
		}

		var oidc = this;
		var complete = function(err, user){
			if(err){
				logger.error(err);
				oidc.fail(err);
			}else{
				logger.trace("complete with result " + user);
				oidc.success(user)
			}
		};

		this.am.validateAccessToken(at).then(function (res) {
			logger.trace("calling verify with result = " + res.result);
            oidc.verify(res.token, res.token.user_tenantname, res.result, complete);
        }).catch(function(err){
        	logger.error(err);
            oidc.fail(err);
        });
	}
}

module.exports = BearerStrategy;
