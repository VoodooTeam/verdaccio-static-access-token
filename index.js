'use strict'

const crypto = require('crypto')
const allowList = []

module.exports = function (config, stuff) {
  stuff.logger.info('Configuring verdaccio-static-token');

  // --- FIX 1: Normalize Config (Handle Verdaccio 6+ Objects) ---
  let tokens = [];
  if (Array.isArray(config)) {
    tokens = config;
  } else if (config && typeof config === 'object') {
    tokens = '0' in config ? Object.values(config) : [config];
  }
  tokens = tokens.filter(t => t && t.token); // Filter invalid
  // -------------------------------------------------------------

  tokens.forEach(_ => { allowList.push(_.token || _) })

  return {
    register_middlewares: function (app, authInstance, storageInstance) {
      console.log('[verdaccio-static-token] register_middlewares loaded')

      // FIX 2: Use the normalized 'tokens' list
      const accessTokens = new Map(tokens
        .map(_ => `Bearer ${_.token}`)
        .map((authHeader, i) => [authHeader, tokens[i]]))

      // FIX 3: Get secret from storageInstance (No require needed!)
      // Verdaccio 6 might hide the secret in 'security.api.jwt.secret', fallback to 'secret'
      const globalConfig = storageInstance.config;
      const verdaccioSecret = globalConfig.security?.api?.jwt?.secret || globalConfig.secret;

      app.use(function (req, res, next) {
        if (req.headers && req.headers.authorization && accessTokens.has(req.headers.authorization)) {
          const overwrite = accessTokens.get(req.headers.authorization)
          
          stuff.logger.warn(`[static-token] Swapping static token for JWT User: ${overwrite.user || 'static-user'}`)
          
          // Generate a REAL JWT compatible with Verdaccio 6
          req.headers.authorization = buildVerdaccio6JWT(
            overwrite.user || 'static-user', 
            verdaccioSecret
          );
        }
        next()
      })

      // --- FIX 4: Valid JWT Generator (HS256) ---
      function buildVerdaccio6JWT(user, secret) {
        // 1. Header
        const header = { alg: 'HS256', typ: 'JWT' };
        
        // 2. Payload (Must include standard Verdaccio groups)
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

        // 3. Signature
        const signature = crypto.createHmac('sha256', secret)
          .update(unsignedToken)
          .digest('base64')
          .replace(/=/g, '')
          .replace(/\+/g, '-')
          .replace(/\//g, '_');

        return `Bearer ${unsignedToken}.${signature}`;
      }
      // ------------------------------------------
    }
  }
}