var express = require('express');
var Webtask = require('webtask-tools');
var bodyParser = require('body-parser');
const {CompactSign} =require('jose/dist/node/cjs/jws/compact/sign');
const { parseJwk } = require('jose/dist/node/cjs/jwk/parse');
const { jwtVerify } = require('jose/dist/node/cjs/jwt/verify');
const crypto = require("crypto");
const uuid = require("uuid");
const axios = require("axios").default;
const qs = require('qs');
var app = express();
const url = require('url');
const querystring = require('querystring');
const { importPKCS8 } = require('jose/dist/node/cjs/key/import');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/.well-known/openid-configuration', (req, res) => {
    const wtUrl = `https://${req.headers.host}/auth0-singpass-extension`;
    res.status(200).send({
        "authorization_endpoint": `${wtUrl}/authorize`,
        "token_endpoint": `${wtUrl}/token`
    });
});

/**
 * /authorize is for embedded QR version of login which is now considered legacy
 */
app.get('/authorize', (req, res) => {
    const context = req.webtaskContext;
    if (!req.query.client_id) {
        return res.send(400, 'missing client_id');
    }
    if (context.data.AUTH0_CLIENT_ID !== req.query.client_id) {
        return res.send(401, 'invalid client_id');
    }
    var url = `https://${context.data.AUTH0_CUSTOM_DOMAIN}${req.url}&ndi_state=${req.query.state}&ndi_nonce=${req.query.code_challenge}&singpass=true`;
    res.redirect(url);
});

/**
 * /auth is for redirect based flow which is the recommended method now
 * note that we probably don't need a new endpoint for redirection since it can all happen with Auth0's native upstream idp parameter mapping.
 */
app.get('/auth', (req, res) => {
    const context = req.webtaskContext;
    if (!req.query.client_id) {
        return res.send(400, 'missing client_id');
    }
    if (context.data.AUTH0_CLIENT_ID !== req.query.client_id) {
        return res.send(401, 'invalid client_id');
    }
    const parsedUrl = url.parse(req.url);
    const queryObj = querystring.parse(parsedUrl.query);
    delete queryObj.client_id;
    const newQueryString = querystring.stringify(queryObj);
    const newUrl = parsedUrl.pathname + '?' + newQueryString;
    
    const finalUrl = `${context.data.SINGPASS_ENVIRONMENT}${newUrl}&client_id=${context.data.SINGPASS_CLIENT_ID}&nonce=${req.query.code_challenge}`;
    res.redirect(finalUrl);
});
app.post('/token', async function (req, res) {
    const context = req.webtaskContext;
    console.log('--- Debugging: Starting /token ---');
    
    const { client_id, client_secret, code, code_verifier, redirect_uri } = req.body;
    console.log("------ context.data.SINGPASS_CLIENT_ID -> "+context.data.SINGPASS_CLIENT_ID);
    if (!client_id || !client_secret) {
        return res.send(400, 'missing client_id / client_secret');
    }
    if (context.data.AUTH0_CLIENT_ID === client_id && context.data.AUTH0_CLIENT_SECRET === client_secret) {
        console.log("------ code_verifier -> "+code_verifier);
        const client_assertion = await generatePrivateKeyJWT(context.data);
        console.log("------ client_assertion -> " + client_assertion);
        
        const qstring = {
            grant_type: 'authorization_code',
            client_id: context.data.SINGPASS_CLIENT_ID,
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion: client_assertion,
            code: code,
            redirect_uri: redirect_uri,
            code_verifier: code_verifier
        };

        console.log("------ qstring -> " + JSON.stringify(qstring));

        var options = {
            method: 'POST',
            url: `${context.data.SINGPASS_ENVIRONMENT}/token`,
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            data: qs.stringify(qstring)
        };
        try {
            console.log("------ request sent -> ");
            const response = await axios.request(options);
            const { id_token } = response.data;
            console.log("------ id_token -> "+id_token);
            const publicKey = await loadPublicKey(context.data);
            const code_v = new TextEncoder().encode(code_verifier);
            const code_v_s256 = crypto.createHash('sha256').update(code_v).digest('base64').replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, '');
            console.log(`nonce expected: ${code_v_s256}`);
            const { payload, protectedHeader } = await jwtVerify(id_token, publicKey, {
                issuer: context.data.ISSUER,
                audience: context.data.CLIENT_ID,
            });
            if (payload.nonce !== code_v_s256) {
                return res.send(400, 'nonce mismatch');
            } else {
                response.data.payload = payload;
                return res.status(200).send(response.data);
            }

        } catch (error) {
            if (error.response) {
                console.dir(error.response.data,{depth:null})
                return res.status(error.response.status).send(error.response.data);
            } else {
                console.log("------ 2. error -> "+error.message);
                // Something happened in setting up the request that triggered an Error
                console.log('Error', error.message);
                return res.status(500).send(error);
            }
        }
    } else {
        return res.send(401, 'invalid request');
    }
});

app.post('/verify', async function (req, res) {
    try {
        const { id_token } = response.body;
        if (!id_token) {
            return res.status(400).send('ID_TOKEN required');
        }
        const publicKey = await loadPublicKey(context.data);
        const { payload, protectedHeader } = await jwtVerify(id_token, publicKey, {
            issuer: context.data.ISSUER,
            audience: context.data.CLIENT_ID
        })
        return res.status(200).send(payload);
    } catch (error) {
        if (error.response) {
            return res.status(error.response.status).send(error.response.data);
        } else {
            // Something happened in setting up the request that triggered an Error
            console.log('Error', error.message);
            return res.status(500).send(error);
        }
    }
})

async function loadPrivateKey(config) {
    console.log('--- Debugging: Starting loadPrivateKey (Manual JWK Method) ---');
    try {
        // Log the raw private key value from config to ensure it's not empty or undefined
        console.log('1. Raw private key string from config (first 30 chars):', config.RELYING_PARTY_PRIVATE_KEY);

        // Log the endpoint we are about to call
        console.log('2. Fetching public key components from JWKS endpoint:', config.RELYING_PARTY_JWKS_ENDPOINT);
        const response = await axios.get(config.RELYING_PARTY_JWKS_ENDPOINT);
        const { keys } = response.data;

        if (!keys || keys.length === 0) {
            console.error('ERROR: No keys found at the JWKS endpoint.');
            throw new Error('No keys found at JWKS endpoint.');
        }

        console.log('3. Successfully fetched public key. Public components are:', JSON.stringify(keys[0]));

        // This is the manual and risky step
        const manuallyConstructedJwk = { ...keys[0] }; // Create a copy
        manuallyConstructedJwk.d = config.RELYING_PARTY_PRIVATE_KEY; // Inject the 'd' parameter

        console.log('4. Manually constructed the full JWK object to be parsed. It includes public parts from the URL and the private part from config.');
        // We log the object without the private key 'd' for security.
        console.log('   JWK structure (excluding "d"):', JSON.stringify({ ...manuallyConstructedJwk, d: '[REDACTED FOR LOGS]' }));

        // Attempt to parse the manually created object
        console.log('5. Calling parseJwk with the manually constructed object...');
        const privateKey = await parseJwk(manuallyConstructedJwk, config.SINGPASS_SIGNING_ALG);
        
        console.log('6. Successfully parsed the manually constructed JWK.');
        return privateKey;

    } catch (e) {
        // This catch block is crucial for proper error reporting.
        console.error('### ERROR in loadPrivateKey ###');
        console.error('An error occurred during the manual JWK construction process.');
        console.error('Error Message:', e.message);
        console.error('Full Error Stack:', e);
        
        // Re-throw the error so the calling function knows something went wrong
        throw e;
    }
};

// async function loadPrivateKey(config) {
//     try {
//         const privateKeyPem_from_config = config.RELYING_PARTY_PRIVATE_KEY;

//         // --- THIS IS THE KEY DEBUGGING STEP ---
//         // Let's print the exact value we are receiving from the configuration.
//         console.log('--- Debugging Key Value ---');
//         console.log('Type:', typeof privateKeyPem_from_config);
//         console.log('Value received from config:', privateKeyPem_from_config);
//         console.log('--- End of Debugging ---');
//         // -----------------------------------------

//         if (!privateKeyPem_from_config || typeof privateKeyPem_from_config !== 'string') {
//              throw new Error("RELYING_PARTY_PRIVATE_KEY is missing, empty, or not a string.");
//         }

//         const privateKeyPem = privateKeyPem_from_config.replace(/\\n/g, '\n');
//         const privateKey = await importPKCS8(privateKeyPem, config.SINGPASS_SIGNING_ALG);
        
//         return privateKey;

//     } catch (e) {
//         console.error("--- FAILED TO PARSE PRIVATE KEY ---");
//         console.error("The private key string from your configuration is likely malformed, empty, or missing.");
//         console.error("Original Error:", e.message);
//         console.error("---------------------------------");
//         throw e;
//     }
// };

async function loadPublicKey(config) {
    try {
        const response = await axios.get(`${config.SINGPASS_ENVIRONMENT}/.well-known/keys`);
        const publicKey = await parseJwk(response.data.keys[0], config.SINGPASS_SIGNING_ALG);
        return publicKey;
    } catch (e) {
        return e;
    }
};

// async function generatePrivateKeyJWT(config) {
//     //const privateKeyPEM = crypto.createPrivateKey(config.PRIVATE_KEY.replace(/\\n/gm, '\n'));
//     const key = await loadPrivateKey(config);
//     const jwt = await new SignJWT({})
//         .setProtectedHeader({ alg: config.SINGPASS_SIGNING_ALG, kid: config.RELYING_PARTY_KID, typ: "JWT" })
//         .setIssuedAt()
//         .setIssuer(config.SINGPASS_CLIENT_ID)
//         .setSubject(config.SINGPASS_CLIENT_ID)
//         .setAudience(config.SINGPASS_ENVIRONMENT)
//         .setExpirationTime('2m') //The expiration time on or after which the JWT MUST NOT be accepted by NDI for processing. Additionally, NDI will not accept tokens with an exp longer than 2 minutes since iat. https://tools.ietf.org/html/rfc7519#section-4.1.4
//         .setJti(uuid.v4())
//         .sign(key);
//     return jwt;
// }

async function generatePrivateKeyJWT(config) {
    
    const ecPrivateKey = await importPKCS8(config.RELYING_PARTY_PRIVATE_KEY, 'ES256');
    // A unique identifier for this specific request, useful for tracing logs.
    const traceId = uuid.v4();
    console.log(`[${traceId}] Attempting to generate Private Key JWT for client: ${config.SINGPASS_CLIENT_ID}`);

    try {
        // --- 1. Load the private key ---
        console.log(`[${traceId}] -> Step 1: Loading private key...`);
       // const key = await loadPrivateKey(config);
        console.log(`[${traceId}] -> Step 1: Private key loaded successfully.`);

        // --- 2. Prepare JWT claims and headers ---
        const jti = uuid.v4(); // Generate the JWT ID
        const claims = {
            iss: config.SINGPASS_CLIENT_ID,
            sub: config.SINGPASS_CLIENT_ID,
            aud: config.SINGPASS_ENVIRONMENT,
            jti: jti,
            iat: Math.floor(Date.now() / 1000),
            exp: '2m'
        };
        const header = {
            alg: config.SINGPASS_SIGNING_ALG,
            kid: config.RELYING_PARTY_KID,
            typ: "JWT"
        };
        
        console.log(`[${traceId}] -> Step 2: Preparing to sign JWT with the following details:`);
        console.log(`   - Header: ${JSON.stringify(header)}`);
        console.log(`   - Claims: ${JSON.stringify(claims)}`);
        console.log(`   - Expiration: 2m`);

        // --- 3. Sign the JWT ---
        const jwt = await new CompactSign(new TextEncoder().encode(JSON.stringify(claims)))
            .setProtectedHeader(header)           
            .sign(ecPrivateKey);

        console.log(`[${traceId}] -> Step 3: JWT signed successfully.`);
        
        // Optionally, log a non-sensitive part of the JWT to confirm it was created.
        // console.log(`[${traceId}] Generated JWT starts with: ${jwt.substring(0, 15)}...`);
        console.log(`[${traceId}] -> Step 4: ${jwt}`);

        return jwt;

    } catch (error) {
        // --- 4. Catch and log any errors ---
        console.error(`### ERROR in generatePrivateKeyJWT [Trace ID: ${traceId}] ###`);
        console.error("An error occurred while generating the client assertion JWT:", error.message);
        
        // Log the full error object for a detailed stack trace.
        console.error("Full error details:", error);
        
        // It's crucial to re-throw the error so the calling function knows something went wrong.
        throw error;
    }
}

module.exports = Webtask.fromExpress(app);
