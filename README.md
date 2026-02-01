# verdaccio-static-access-token
Static access token middleware plugin for Verdaccio 6+

## Installation

```bash
npm install verdaccio-static-access-token
```

## Usage

Add the plugin to the `middlewares` section in your `config.yaml`:

```yaml
middlewares:
  static-access-token:
    enabled: true
    tokens:
      - key: my-super-secret-token
        user: ci-bot
        readonly: true
      - key: my-super-secret-token-with-publish-access
        user: ci-bot-publisher
        readonly: false

# You still need an auth plugin. For example, the default one:
auth:
  htpasswd:
    file: ./htpasswd

# You can now use your ci-bot user to define their permissions
packages:
  '@*/*':
    access: $authenticated
    publish: ci-bot-publisher
    unpublish: ci-bot-publisher

  '**':
    access: $authenticated
    publish: ci-bot-publisher
    unpublish: ci-bot-publisher
```
