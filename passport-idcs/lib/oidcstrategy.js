/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

/*
DESCRIPTION
IDCS server's passport authentication strategy.

MODIFIED    (MM/DD/YY)
xinnwang    12/06/16 - Refacotoring
junyhe      11/18/16 - Creation
 */
'use strict';

// core module
const passport = require('passport');

// project module
const Logger = require('./logger');
const CONSTANTS = require('./constants');
const UserManager = require('./idcsusermanager');
const IdcsAuthenticationManager = require('./idcsauthenticationmanager');
// id token header name
const ID_TOKEN_HEADER_KEY = 'idcs_user_assertion';
const USER_ID_HEADER_KEY = "idcs_user_id";
// user tenant header name
const TENANT_HEADER_KEY = 'x-user-identity-domain-name';

class OIDCStrategy extends passport.Strategy {
	/**
	 * Constructor for OIDCStrategy
	 *  @constructor
	 *  @param {Object}       options Configurations for idcs oidc strategy.
	 * - IDCSHost             Required, IDCS host address. e.g. https://%tenant%.idcspool0.identity.c9dev0.oraclecorp.com
	 * - ClientTenant         Required, OAuth client tenant
	 * - ClientId             Required, OAuth client id
	 * - ClientSecret         Required, OAuth client secret
	 * - AudienceServiceUrl   Required, for token validation
     * - TokenIssuer          Required, for token validation
     * - CrossTenant          Optional, set true for Cross tenant use cases
	 * - TokenClockSkew       Optional, number of seconds to tolerate when checking the nbf and exp claims, to deal with small clock differences among different servers, default: 120
	 * - LogLevel             Optional, set logging level, default level: warn
	 * @param {Function} verify
	 * @access public
	 */
	constructor(options, verify) {
		super();

		// verify configurations
		this.options = CONSTANTS.validateOptions(options);
		this.name = 'IDCSOIDC';
		this.verify = verify;

		Logger.setLevel(this.options[CONSTANTS.LOG_LEVEL]);
		this.logger = Logger.getLogger('OIDCStrategy');
		this.logger.trace("OIDC Strategy, constructor, options: "+ options +", options after handling: "+this.options);

		var verifyClaims = {
			clockTolerance: this.options[CONSTANTS.TOKEN_CLOCK_SKEW]
		};
		if (this.options[CONSTANTS.TOKEN_CLAIM_ISSUER]) {
			verifyClaims.issuer = this.options[CONSTANTS.TOKEN_CLAIM_ISSUER];
		}

		this.metadataUrl = this.options[CONSTANTS.IDCSHost] + CONSTANTS.DISCOVERY_PATH;
        this.am  = new  IdcsAuthenticationManager(this.options);

	}

	getMetadataUrl(tenant) {
		return this.metadataUrl.replace('%tenant%', tenant);
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
		logger.trace("OIDC Strategy, authenticate, headers: "+  JSON.stringify(req.headers) +", options: "+ options);

		var idToken = req.headers[ID_TOKEN_HEADER_KEY];
		//var userId = req.headers[USER_ID_HEADER_KEY];
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

		if(idToken){
			this.am.validateIdToken(idToken).then(function (res) {
                logger.trace("calling verify with result = " + res.result);
                oidc.verify(res.token, res.token.user_tenantname, res.result, complete);
            }).catch(function(err){
                logger.error(err);
                oidc.fail(err);
            });
		}else{
			var err = "missing "+ ID_TOKEN_HEADER_KEY +" and in the header";
			logger.error(err);
			return this.fail(err);
		}
	}
}

module.exports = OIDCStrategy;
