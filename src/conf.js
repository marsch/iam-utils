
const CONFIG = {

    issuer: process.env.IAM_JWT_ISSUER || 'https://www.example.com',
    audience: process.env.IAM_JWT_AUDIENCE || 'example.com',
    hmacSecret: process.env.IAM_JWT_HMAC_SECRET || 'example',
    jwksUri: process.env.IAM_JWKS_URI || 'http://localhost:3099/.well-known/jwks.json'

};

module.exports = CONFIG;