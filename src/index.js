const Logger = require('@basaas/node-logger');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const log = Logger.getLogger(`iam-middleware`);

const CONF = require('./conf');

log.info('iam-middleware config', CONF);

const client = jwksClient({
    strictSsl: true,
    cache: true,
    cacheMaxEntries: 5,
    cacheMaxAge: 3600 * 1000 * 2, // 2h in ms
    jwksUri: CONF.jwksUri
});

const getKey = (header, callback) =>{
    client.getSigningKey(header.kid, (err, key) => {
        let signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
    });
};


const decodeHeader = (token) => {
    const tokenBlocks = token.split('.');
    if(tokenBlocks.length !== 3) {
        throw new Error('Invalid token. Token does not contain three parts.')
    }

    return JSON.parse(Buffer.from(tokenBlocks[0], 'base64').toString());

};


const getJwtOptions = (opts = {}) => {
    return Object.assign({}, {
        issuer: CONF.issuer,
        audience: CONF.audience,
    }, opts);
};


module.exports = {

    verify: (token) => {

        return new Promise((resolve, reject) => {

            const alg = decodeHeader(token).alg;

            let secret;

            if(alg.indexOf('RS') === 0) {
                console.info('Received RS-ALG', alg);
                secret = getKey;
            } else if(alg.indexOf('HS') === 0) {
                console.info('Received HS-ALG', alg);
                secret = CONF.hmacSecret;
            } else {
                return reject(`Unsupported algorithm ${alg}`);
            }

            jwt.verify(token, secret, getJwtOptions(), function(err, decoded) {
                if(err) {
                    log.debug(` Token ${err.name === 'TokenExpiredError' ? 'expired' : 'invalid'}`, err);
                    return reject(err);
                }
                return resolve(decoded);
            });
        });


    },

    middleware: async (req, res, next) => {

        let payload = null;

        if (!req.headers.authorization) {
            return next({ status: 401, message: 'Missing authorization header.' });
        }

        try {
            const header = req.headers.authorization.split(' ');
            if (!header || header.length < 2) {
                log.debug('Authorization header length is incorrect');
                return next({ status: 401, message: 'Invalid authorization header' });
            }
            const token = header[1];
            payload = await module.exports.verify(token);
        } catch (err) {
            log.debug('Failed to parse token', err);
            return next({ status: 401, message: `Token invalid. Error: ${err.name}. Details: ${err.message}` });
        }

        if (payload) {
            req.__HEIMDAL__ = req.__HEIMDAL__ || {};
            req.__HEIMDAL__.token = req.headers.authorization;
            req.__HEIMDAL__.auth = payload;
            req.__HEIMDAL__.username = payload.username;
            req.__HEIMDAL__.userid = payload.sub;
            req.__HEIMDAL__.memberships = payload.memberships;
            req.__HEIMDAL__.role = payload.role;
            return next();
        } else {
            log.error('JWT payload is empty or undefined', { payload });
            return next({ status: 400, message: 'JWT payload is either empty or undefined' });
        }


    }

};