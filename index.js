var express = require('express');
var Webtask = require('webtask-tools');
var bodyParser = require('body-parser');
const { SignJWT } = require('jose/dist/node/cjs/jwt/sign');
const { parseJwk } = require('jose/dist/node/cjs/jwk/parse');
const { jwtVerify } = require('jose/dist/node/cjs/jwt/verify');
const crypto = require("crypto");
const uuid = require("uuid");
const axios = require("axios").default;
const qs = require('qs');
var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/.well-known/openid-configuration', (req, res) => {
    const wtUrl = `https://${req.headers.host}/auth0-singpass-extension`;
    res.status(200).send({
        "authorization_endpoint": `${wtUrl}/authorize`,
        "token_endpoint": `${wtUrl}/token`
    });
});
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

app.post('/token', async function (req, res) {
    const context = req.webtaskContext;
    const { client_id, client_secret, code, code_verifier, redirect_uri } = req.body;
    if (!client_id || !client_secret) {
        return res.send(400, 'missing client_id / client_secret');
    }
    if (context.data.AUTH0_CLIENT_ID === client_id && context.data.AUTH0_CLIENT_SECRET === client_secret) {
        const client_assertion = await generatePrivateKeyJWT(context.data);
        var options = {
            method: 'POST',
            url: `${context.data.SINGPASS_ENVIRONMENT}/token`,
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            data: qs.stringify({
                grant_type: 'authorization_code',
                client_id: context.data.SINGPASS_CLIENT_ID,
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                client_assertion: client_assertion,
                code: code,
                redirect_uri: redirect_uri
            })
        };
        try {
            const response = await axios.request(options);
            const { id_token } = response.data;
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
                return res.status(error.response.status).send(error.response.data);
            } else {
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
    try {
        const response = await axios.get(config.RELYING_PARTY_JWKS_ENDPOINT);
        const { keys } = response.data;
        keys[0].d = config.RELYING_PARTY_PRIVATE_KEY;
        return await parseJwk(keys[0], config.SINGPASS_SIGNING_ALG);;
    } catch (e) {
        return e;
    }
};

async function loadPublicKey(config) {
    try {
        const response = await axios.get(`${config.SINGPASS_ENVIRONMENT}/.well-known/keys`);
        const publicKey = await parseJwk(response.data.keys[0], config.SINGPASS_SIGNING_ALG);
        return publicKey;
    } catch (e) {
        return e;
    }
};

async function generatePrivateKeyJWT(config) {
    //const privateKeyPEM = crypto.createPrivateKey(config.PRIVATE_KEY.replace(/\\n/gm, '\n'));
    const key = await loadPrivateKey(config);
    const jwt = await new SignJWT({})
        .setProtectedHeader({ alg: config.SINGPASS_SIGNING_ALG, kid: config.RELYING_PARTY_KID, typ: "JWT" })
        .setIssuedAt()
        .setIssuer(config.SINGPASS_CLIENT_ID)
        .setSubject(config.SINGPASS_CLIENT_ID)
        .setAudience(config.SINGPASS_ENVIRONMENT)
        .setExpirationTime('2m') //The expiration time on or after which the JWT MUST NOT be accepted by NDI for processing. Additionally, NDI will not accept tokens with an exp longer than 2 minutes since iat. https://tools.ietf.org/html/rfc7519#section-4.1.4
        .setJti(uuid.v4())
        .sign(key);
    return jwt;
}


module.exports = Webtask.fromExpress(app);
