/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

/*
DESCRIPTION
constants for this module.

MODIFIED    (MM/DD/YY)

xinnwang    12/06/16 - Remove unnecessary constant
junyhe      11/18/16 - Creation
 */
'use strict';

const CONSTANTS = {
	//signed key file path key
	JWKS_URI: 'JwksUri',

	// verifying claims
	TOKEN_CLOCK_SKEW: 'TokenClockSkew',
	TOKEN_CLOCK_SKEW_DEFAULT: 300,
	TOKEN_CLAIM_ISSUER: 'TokenClaimIssuer',

	// identity service host
	IDCSHost: 'IDCSHost',
	// oauth client id key
	CLIENT_ID: 'ClientId',
	// oauth client secret key
	CLIENT_SECRET: 'ClientSecret',
	// oauth client tenant key
	CLIENT_TENANT: 'ClientTenant',

	AUDIENCE_SERVICE_URL : "AudienceServiceUrl",
	RESOURCE_TENANCY : "ResourceTenancy",
	CROSS_TENANT : "CrossTenant",
	TOKEN_ISSUER : "TokenIssuer",
	TOKEN_VALIDATION_LEVEL : "TokenValidationLevel",
	FULLY_QUALIFIED_SCOPES : "FullyQualifiedScopes",

	// meta data cache key
	META_DATA_CACHE_TTL: 'MetaDataCacheTTL',
	// default metadata cache ttl is 1 day
	META_DATA_CACHE_TTL_DEFAULT: 86400,

	// meta data cache max size key
	META_DATA_CACHE_MAX_SIZE: 'MetaDataCacheMaxSize',
	// default meta data cache max size
	META_DATA_CACHE_MAX_SIZE_DEFAULT: 1000,

	// token timeout window
	TOKEN_TIMEOUT_WINDOW: 'tokenTimeoutWindow',
	// default token timeout window
	TOKEN_TIMEOUT_WINDOW_DEFAULT: 60 * 5,

	// logging level key
	LOG_LEVEL: 'LogLevel',
	LOG_LEVELS: ['fatal', 'error', 'warn', 'info', 'debug', 'trace'],
	DISCOVERY_PATH: '/.well-known/idcs-configuration',

	// IDCS configurations can be get from environment varibles
	IDCS_ENV_VARIABLES: ['ORA_IDCS_CLIENT_TENANT', 'ORA_IDCS_CLIENT_ID', 'ORA_IDCS_CLIENT_SECRET', 'ORA_IDCS_HOST', 'ORA_IDCS_PORT', 'ORA_IDCS_AUDIENCE_URL', 'ORA_IDCS_ISSUER_URL'],

	ORA_IDCS_CROSS_TENANT : "ORA_IDCS_CROSS_TENANT",
	ORA_IDCS_RESOURCE_TENANCY : "ORA_IDCS_RESOURCE_TENANCY",
	ORA_IDCS_TOKEN_VALIDATION_LEVEL : "ORA_IDCS_TOKEN_VALIDATION_LEVEL",
	ORA_IDCS_FQS_RESOURCE : "ORA_IDCS_FQS_RESOURCE"

};

/**
 * Populate oauth client name, id, tenant name
 * @param {Object} authticatedUser - authenticated user object
 * @param {Object} verifiedToken - verified IT/AT object
 * @param {Boolean} populateScopeAndAud - indicates whether populate oauth scope, audience
 */
CONSTANTS.populateClientClaims = function (authticatedUser, verifiedToken) {
	let authResult = authticatedUser || {};

	authResult.client = {
		'client_name': verifiedToken.client_name,
		'client_id': verifiedToken.client_id,
		'client_tenantname': verifiedToken.client_tenantname,
		'scope': verifiedToken.scope,
		'audience': verifiedToken.aud
	};

	return authResult;
};

/**
 * Create and populate authenticated user object
 * @param {Object} verifiedToken - verified IT/AT object
 */
CONSTANTS.populateAuthenticatedUser = function (verifiedToken) {
	let user = {
		name: verifiedToken.sub,
		displayName: verifiedToken.user_displayname,
		id: verifiedToken.user_id,
		tenant: verifiedToken.user_tenantname,
		groups: verifiedToken.groups ? verifiedToken.groups.map((group) => {
			return {
				'name': group.name,
				'id': group.id,
				'location': group.$ref
			};
		}) : [],
		appRoles: verifiedToken.appRoles ? verifiedToken.appRoles.map((role) => {
			return {
				'name': role.displayName,
				'id': role.id,
				'location': role.$ref,
				'appName': role.appName,
				'appID': role.appID
			};
		}) : []
	};

	return user;
};


CONSTANTS.populateUserFromIdcsUserObject = function(idcsUser, tenant){
	let user = {
		name: idcsUser.userName,
		displayName: idcsUser.displayName,
		id: idcsUser.id,
		tenant: tenant,
		groups: idcsUser.groups ? idcsUser.groups.map((group) => {
			return {
				'name': group.display,
				'id': group.value,
				'location': group.$ref
			};
		}) : [],
		appRoles: idcsUser["urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User"].appRoles ? idcsUser["urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User"].appRoles.map((role) => {
			return {
				'name': role.display,
				'id': role.value,
				'location': role.$ref,
				'appName': role.appName,
				'appID': role.appID
			};
		}) : []
	};

	return user;
};



/**
 * Populate granted groups and app roles
 * @param {Object} user - authenticated user object
 * @param {Object} userAssertResult - query result get from user asserter endpoint
 */
CONSTANTS.populateGroupAndRoles = function (user, userAssertResult) {
	let retUser = user || {};
	retUser.groups = userAssertResult.groups ? userAssertResult.groups.map((group) => {
			return {
				'name': group.display,
				'id': group.value,
				'location': group.$ref
			};
		}) : [];
	retUser.appRoles = userAssertResult.appRoles ? userAssertResult.appRoles.map((role) => {
			return {
				'name': role.display,
				'id': role.value,
				'location': role.$ref,
				'appName': role.appName,
				'appID': role.appId
			};
		}) : [];

	return retUser;
};

/**
 * Validate and set default values for input options
 * @param {Object} options - input options
 */
CONSTANTS.validateOptions = function (options) {
	if (!options) {
		throw new Error(`options is null or empty`);
	}

	// whether the IDCS properties will be override by environment variables
	let overideByEnv = true;
	for (let name of CONSTANTS.IDCS_ENV_VARIABLES) {
		let value = process.env[name];
		if (!value) {
			overideByEnv = false;
			break;
		}
	}

	if (overideByEnv) {
		options[CONSTANTS.CLIENT_TENANT] = process.env[CONSTANTS.IDCS_ENV_VARIABLES[0]];
		options[CONSTANTS.CLIENT_ID] = process.env[CONSTANTS.IDCS_ENV_VARIABLES[1]];
		options[CONSTANTS.CLIENT_SECRET] = process.env[CONSTANTS.IDCS_ENV_VARIABLES[2]];
		options[CONSTANTS.IDCSHost] = `https://%tenant%.${process.env[CONSTANTS.IDCS_ENV_VARIABLES[3]]}:${process.env[CONSTANTS.IDCS_ENV_VARIABLES[4]]}`;
		options[CONSTANTS.AUDIENCE_SERVICE_URL] = process.env[CONSTANTS.IDCS_ENV_VARIABLES[5]];
		options[CONSTANTS.TOKEN_ISSUER] = process.env[CONSTANTS.IDCS_ENV_VARIABLES[6]];
		options[CONSTANTS.CROSS_TENANT] = process.env[CONSTANTS.ORA_IDCS_CROSS_TENANT];
		options[CONSTANTS.RESOURCE_TENANCY] = process.env[CONSTANTS.ORA_IDCS_RESOURCE_TENANCY];
		options[CONSTANTS.TOKEN_VALIDATION_LEVEL] = process.env[CONSTANTS.ORA_IDCS_TOKEN_VALIDATION_LEVEL];
		options[CONSTANTS.FULLY_QUALIFIED_SCOPES] = process.env[CONSTANTS.ORA_IDCS_FQS_RESOURCE];
	}

	if (!options[CONSTANTS.IDCSHost]) {
		throw new Error(`IDCS host missing`);
	}

	// verify oauth clients
	if (!options[CONSTANTS.CLIENT_ID] || !options[CONSTANTS.CLIENT_SECRET]) {
		throw new Error(`invalid oauth client, client id: ${options[CONSTANTS.CLIENT_ID]}, client secret: ${options[CONSTANTS.CLIENT_SECRET]}}`);
	}
	// log level
	let logLevel = options[CONSTANTS.LOG_LEVEL];
	let validLevels = CONSTANTS.LOG_LEVELS;
	if (logLevel) {
		if (validLevels.indexOf(logLevel) == -1) {
			this.logger.warn(`invalid log level: ${logLevel}`);
			// set to error level by default
			options[CONSTANTS.LOG_LEVEL] = validLevels[2];
		}
	} else {
		options[CONSTANTS.LOG_LEVEL] = validLevels[2];
	}

	// cache size
	let cacheSize = options[CONSTANTS.META_DATA_CACHE_MAX_SIZE];
	if (!cacheSize || Number.parseInt(cacheSize) <= 0) {
		options[CONSTANTS.META_DATA_CACHE_MAX_SIZE] = CONSTANTS.META_DATA_CACHE_MAX_SIZE_DEFAULT;
	}

	// cache ttl
	let cacheTTL = options[CONSTANTS.META_DATA_CACHE_TTL];
	if (!cacheTTL || Number.parseInt(cacheTTL) <= 0) {
		options[CONSTANTS.META_DATA_CACHE_TTL] = CONSTANTS.META_DATA_CACHE_TTL_DEFAULT;
	}

	// access token timeout window size
	let tokenTimeoutWindow = options[CONSTANTS.TOKEN_TIMEOUT_WINDOW];
	if (!tokenTimeoutWindow) {
		options[CONSTANTS.TOKEN_TIMEOUT_WINDOW] = CONSTANTS.TOKEN_TIMEOUT_WINDOW_DEFAULT;
	}

	// token clock skew
	let clockSkew = options[CONSTANTS.TOKEN_CLOCK_SKEW];
	if (!clockSkew || Number.parseInt(clockSkew) <= 0) {
		options[CONSTANTS.TOKEN_CLOCK_SKEW] = CONSTANTS.TOKEN_CLOCK_SKEW_DEFAULT;
	}

	return options;
};

module.exports = CONSTANTS;
