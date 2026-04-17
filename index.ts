import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';

const LOG_TAG = 'verdaccio-static-access-token';
const MIN_TOKEN_LENGTH = 32;

interface StaticTokenConfig {
  key: string;
  user: string;
  readonly?: boolean;
}

interface PluginConfig {
  enabled?: boolean;
  tokens?: StaticTokenConfig[];
}

interface PluginStuff {
  logger: {
    info: (msg: string) => void;
    warn: (msg: string) => void;
    error: (msg: string) => void;
  };
}

interface StorageConfig {
  config: {
    secret?: string;
    security?: {
      api?: {
        jwt?: {
          secret?: string;
        };
      };
    };
  };
}

class StaticAccessTokenMiddleware {
  private readonly stuff: PluginStuff;
  private readonly enabled: boolean;
  private readonly tokens: StaticTokenConfig[];

  constructor(config: PluginConfig | undefined, stuff: PluginStuff) {
    this.stuff = stuff;
    this.stuff.logger.info(`[${LOG_TAG}] Configuring`);

    this.enabled = config != null && config.enabled !== false;

    if (!this.enabled) {
      this.stuff.logger.info(`[${LOG_TAG}] Disabled`);
      this.tokens = [];
      return;
    }

    this.tokens = config?.tokens ?? [];
  }

  // eslint-disable-next-line camelcase
  register_middlewares(
    app: { use: (fn: (req: Request, res: Response, next: NextFunction) => void) => void },
    _authInstance: unknown,
    storageInstance: StorageConfig
  ): void {
    if (!this.enabled) {
      return;
    }
    if (!this.tokens.length) {
      this.stuff.logger.error(
        `[${LOG_TAG}] No tokens configured, skipping middleware setup`
      );
      return;
    }

    const globalConfig = storageInstance.config;
    const verdaccioSecret =
      globalConfig.security?.api?.jwt?.secret ?? globalConfig.secret;

    if (!verdaccioSecret || verdaccioSecret.trim() === '') {
      this.stuff.logger.warn(
        `[${LOG_TAG}] No JWT secret configured (security.api.jwt.secret or secret). Skipping middleware.`
      );
      return;
    }

    for (const t of this.tokens) {
      if (!t?.key || !t?.user) {
        throw new Error(
          `[${LOG_TAG}] A token is missing a key or user.`
        );
      }
      if (t.key.length < MIN_TOKEN_LENGTH) {
        throw new Error(
          `[${LOG_TAG}] Token "${t.key}" for user "${t.user}" is too insecure. Must be at least ${MIN_TOKEN_LENGTH} characters long.`
        );
      }
    }

    this.stuff.logger.info(
      `[${LOG_TAG}] register_middlewares loaded ${this.tokens.length} tokens`
    );

    const hashHeader = (header: string): string =>
      crypto.createHash('sha256').update(header).digest('hex');

    const accessTokens = new Map(
      this.tokens.map((t) => [
        hashHeader(`Bearer ${Buffer.from(t.key).toString('base64')}`),
        t,
      ] as const)
    );

    app.use((req: Request, res: Response, next: NextFunction) => {
      if (!req.headers?.authorization) {
        return next();
      }

      const overwrite = accessTokens.get(hashHeader(req.headers.authorization));
      if (overwrite) {
        if (overwrite.readonly) {
          const writeMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];
          if (writeMethods.includes(req.method.toUpperCase())) {
            this.stuff.logger.warn(
              `[${LOG_TAG}] Read-only token used for write method: ${req.method} ${req.url}`
            );
            return res.status(403).send('Forbidden: Read-only token');
          }
        }

        this.stuff.logger.info(
          `[${LOG_TAG}] Swapping static token for JWT User: ${overwrite.user}`
        );

        req.headers.authorization = this.buildVerdaccio6JWT(
          overwrite.user,
          verdaccioSecret,
          overwrite.readonly ?? false
        );
      }
      next();
    });
  }

  private buildVerdaccio6JWT(
    user: string,
    secret: string,
    readonly: boolean
  ): string {
    const header = { alg: 'HS256', typ: 'JWT' as const };

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      name: user,
      groups: readonly
        ? ['$all', '$authenticated', 'ci-readonly']
        : [
            '$all',
            '$authenticated',
            '@all',
            '@authenticated',
            'ci-readwrite',
          ],
      iat: now,
      exp: now + 60 * 60 * 24,
      iss: LOG_TAG,
      aud: 'verdaccio-registry',
      jti: crypto.randomUUID(),
    };

    const base64Url = (obj: object): string =>
      Buffer.from(JSON.stringify(obj))
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');

    const encodedHeader = base64Url(header);
    const encodedPayload = base64Url(payload);
    const unsignedToken = `${encodedHeader}.${encodedPayload}`;

    const signature = crypto
      .createHmac('sha256', secret)
      .update(unsignedToken)
      .digest('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

    return `Bearer ${unsignedToken}.${signature}`;
  }
}

function plugin(config: PluginConfig | undefined, stuff: PluginStuff): StaticAccessTokenMiddleware {
  return new StaticAccessTokenMiddleware(config, stuff);
}

export = plugin;
