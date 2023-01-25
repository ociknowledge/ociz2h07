var ids = {
    oracle: {
        "ClientId": "00000000000000000000000000000000",
        "ClientSecret": "00000000-0000-0000-0000-000000000000",
        "ClientTenant": "idcs-00000000000000000000000000000000",
        "IDCSHost": "https://%tenant%.identity.oraclecloud.com",
        "AudienceServiceUrl": "https://idcs-00000000000000000000000000000000.identity.oraclecloud.com:443",
        "TokenIssuer": "https://identity.oraclecloud.com/",
        "scope": "urn:opc:idm:t.user.me openid",
        "logoutSufix": "/oauth2/v1/userlogout",
        "redirectURL": "http://0.0.0.0:3000/callback",
        "mainURL": "http://0.0.0.0:3000/",
        "LogLevel": "warn",
        "ConsoleLog": "False"
    }
};

module.exports = ids;