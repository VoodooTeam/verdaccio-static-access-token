'use strict'

const crypto = require('crypto')

class StaticAccessTokenMiddleware {
  constructor(config, stuff) {
    this.stuff = stuff
    this.stuff.logger.info('Configuring verdaccio-static-token');
    
    // --- FIX 1: Normalize Config (Handle Verdaccio 6+ Objects) ---
    let tokens = [];
    if (Array.isArray(config)) {
      tokens = config;
    } else if (config && typeof config === 'object') {
      tokens = '0' in config ? Object.values(config) : [config];
    }
    this.tokens = tokens.filter(t => t && t.token); // Filter invalid
    // -------------------------------------------------------------
    
    this.allowList = this.tokens.map(_ => _.token || _);
  }

  register_middlewares(app, authInstance, storageInstance) {
    this.stuff.logger.info('[verdaccio-static-token] register_middlewares loaded')

    // Create a map of 'Bearer <token>' to token config for quick lookup
    const accessTokens = new Map(this.tokens
      .map(_ => `Bearer ${_.token}`)
      .map((authHeader, i) => [authHeader, this.tokens[i]]))

    // Verdaccio 6 might hide the secret in 'security.api.jwt.secret', fallback to 'secret'
    const globalConfig = storageInstance.config;
    const verdaccioSecret = globalConfig.security?.api?.jwt?.secret || globalConfig.secret;

    app.use((req, res, next) => {
      if (req.headers && req.headers.authorization && accessTokens.has(req.headers.authorization)) {
        const overwrite = accessTokens.get(req.headers.authorization)
        
        this.stuff.logger.warn(`[static-token] Swapping static token for JWT User: ${overwrite.user || 'static-user'}`)
        
        // Generate a REAL JWT compatible with Verdaccio 6
        req.headers.authorization = this._buildVerdaccio6JWT(
          overwrite.user || 'static-user', 
          verdaccioSecret
        );
      }
      next()
    })
  }

  // --- FIX 4: Valid JWT Generator (HS256) ---
  _buildVerdaccio6JWT(user, secret) {
    // Header
    const header = { alg: 'HS256', typ: 'JWT' };
    
    // Payload (Must include standard Verdaccio groups)
    const payload = {
      name: user,
      groups: ['$all', '$authenticated', '@all', '@authenticated'],
      iat: Math.floor(Date.now() / 1000), // Issued at now
      exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24) // Expires in 1 day
    };

    // Helper for Base64URL encoding (required for JWT)
    const base64Url = (obj) => Buffer.from(JSON.stringify(obj))
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

    const encodedHeader = base64Url(header);
    const encodedPayload = base64Url(payload);
    const unsignedToken = `${encodedHeader}.${encodedPayload}`;

    // Signature
    const signature = crypto.createHmac('sha256', secret)
      .update(unsignedToken)
      .digest('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

    return `Bearer ${unsignedToken}.${signature}`;
  }
}

module.exports = (config, stuff) => {
  return new StaticAccessTokenMiddleware(config, stuff);
};