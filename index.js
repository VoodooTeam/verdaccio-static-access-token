'use strict'

const crypto = require('crypto')

class StaticAccessTokenMiddleware {
  constructor(config, stuff) {
    this.stuff = stuff;
    this.stuff.logger.info('Configuring verdaccio-static-token');

    if (!config || config.enabled === false) {
      this.stuff.logger.info('verdaccio-static-token is disabled');
      this.tokens = [];
      return;
    }

    this.tokens = config.staticAccessTokens || [];
  }

  register_middlewares(app, authInstance, storageInstance) {
    this.tokens.forEach(t => {
      if (!t || !t.key || !t.user) {
        throw new Error('A token is missing a key or user.');
      }
      if (t.key.length < 16) {
        throw new Error(`Token "${t.key}" for user "${t.user}" is too insecure. Must be at least 16 characters long.`);
      }
    });

    this.stuff.logger.info(`Loaded ${this.tokens.length} static access tokens.`);

    if (!this.tokens.length) {
      return;
    }

    this.stuff.logger.info('[verdaccio-static-token] register_middlewares loaded')

    // Create a map of 'Bearer <token>' to token config for quick lookup
    const accessTokens = new Map(this.tokens
      .map(_ => `Bearer ${_.key}`)
      .map((authHeader, i) => [authHeader, this.tokens[i]]))


    // Verdaccio 6 might hide the secret in 'security.api.jwt.secret', fallback to 'secret'
    const globalConfig = storageInstance.config;
    const verdaccioSecret = globalConfig.security?.api?.jwt?.secret || globalConfig.secret;

    app.use((req, res, next) => {

      // Check if the authorization header is valid and present in the request
      if (!req.headers || !req.headers.authorization) {
        return next()
      }

      if (req.headers && req.headers.authorization && accessTokens.has(req.headers.authorization)) {
        const overwrite = accessTokens.get(req.headers.authorization)        

        // If the token is read-only we should forbid write methods
        if (overwrite.readonly) {
          const writeMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];
          if (writeMethods.includes(req.method.toUpperCase())) {
            this.stuff.logger.warn(`[static-token] Read-only token used for write method: ${req.method} ${req.url}`);
            return res.status(403).send('Forbidden: Read-only token');
          }
        }
        
        this.stuff.logger.info(`[static-token] Swapping static token for JWT User: ${overwrite.user || 'static-user'}`)
        
        // Generate a REAL JWT compatible with Verdaccio 6
        req.headers.authorization = this._buildVerdaccio6JWT(
          overwrite.user || 'static-user',
          verdaccioSecret,
          overwrite.readonly
        );
      }
      next()
    })
  }

  // --- FIX 4: Valid JWT Generator (HS256) ---
  _buildVerdaccio6JWT(user, secret, readonly) {
    // Header
    const header = { alg: 'HS256', typ: 'JWT' };
    
    // Payload (Must include standard Verdaccio groups)
    const payload = {
      name: user,
      groups: readonly ? ['$all', '$authenticated'] : ['$all', '$authenticated', '@all', '@authenticated'],
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