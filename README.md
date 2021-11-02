# Auth0 - Singpass Extesion

[![Auth0 Extensions](http://cdn.auth0.com/extensions/assets/badge.svg)]()

This extension will expose endpoints you can use from your custom social connection to support Singpass token endpoint with client-assertion.


## Usage

Once the webtask has been deployed you will need the following endpoints to complete the setup for the custom social connection

You can use the following url to get the below values
```
https://{TENANT}.{region}12.webtask.io/auth0-singpass-extension/.well-known/openid-configuration
```

For Custom Social Connection
```
authorizeUrl = 'https://{TENANT}.{region}12.webtask.io/auth0-singpass-extension/authorize'
tokenURL = 'https://{TENANT}.{region}12.webtask.io/auth0-singpass-extension/token'
```


## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, amont others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a free Auth0 Account

1. Go to [Auth0](https://auth0.com) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.

## License

This project is licensed under the MIT license.
