
const CONFIG = {

    issuer: process.env.IAM_JWT_ISSUER || 'https://www.example.com',
    audience: process.env.IAM_JWT_AUDIENCE || 'example.com',
    hmacSecret: process.env.IAM_JWT_HMAC_SECRET || 'example',
    iamBaseUrl: process.env.IAM_BASE_URL || 'http://localhost:3099',

    getJwksUri: () => `${CONFIG.iamBaseUrl}/.well-known/jwks.json`,
    getUserData: () => `${CONFIG.iamBaseUrl}/api/v1/users/:id`,
    getTenantData: () => `${CONFIG.iamBaseUrl}/api/v1/tenants/:id`,
    getUserAndTenantData: () => `${CONFIG.iamBaseUrl}/token`,

};

module.exports = CONFIG;