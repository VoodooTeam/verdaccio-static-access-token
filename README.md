# Verdaccio Static Access Token
[![npm version](https://img.shields.io/npm/v/verdaccio-static-access-token.svg)](https://www.npmjs.com/package/verdaccio-static-access-token)

Static access token middleware plugin for **Verdaccio 6+**. This plugin allows you to define a list of static tokens for authentication, which is particularly useful for CI/CD pipelines where you might not want to use `npm login`.

## Installation

```bash
npm install verdaccio-static-access-token
```
or
```bash
yarn add verdaccio-static-access-token
```

## Local Development

For development, you can install the plugin locally by specifying the path to the plugin directory in your `config.yaml` file. This is useful if you are making changes to the plugin and want to test them in a live Verdaccio environment without publishing to npm.

First, you need to add the plugin to the `middlewares` section as you would normally do. Then, you need to add the path to your plugin to the `plugins` section.

```yaml
# Add the plugin to your middlewares
middlewares:
  static-access-token:
    enabled: true
    # Your token configuration...

# Add the path to your plugin folder
plugins: /path/to/your/plugins
```

Make sure to replace `/path/to/your/plugins` with the actual path to the plugin's directory on your local machine.

## Configuration

Add `static-access-token` to the `middlewares` section in your Verdaccio `config.yaml` file.

```yaml
middlewares:
  static-access-token:
    # Whether the plugin is enabled or not
    enabled: true
    # A list of tokens
    tokens:
      # A token with read-only access
      - key: "my-super-secret-token"
        user: "ci-bot"
        readonly: true
      # A token with read-write access
      - key: "my-super-secret-token-with-publish-access"
        user: "ci-bot-publisher"
        readonly: false
```

### Options

| Name      | Type    | Description                                                                                             |
| --------- | ------- | ------------------------------------------------------------------------------------------------------- |
| `enabled` | boolean | Enables or disables the plugin. Default is `true`.                                                      |
| `tokens`  | array   | A list of token configurations.                                                                         |
| `key`     | string  | **Required.** The static token. It must be at least 32 characters long.                                 |
| `user`    | string  | **Required.** The user name that will be associated with the token.                                     |
| `readonly`| boolean | If `true`, the token will only have read access. Write actions like `publish` will be forbidden. Default is `false`. |

## Usage

Once the plugin is configured, you can use the tokens to authenticate with Verdaccio. The token must be **base64 encoded** before being used.

You can encode your token using the following command:

```bash
echo -n "my-super-secret-token" | base64
```

### NPM

Set the base64 encoded token in your `.npmrc` file:

```
//my-verdaccio-registry.com/:_authToken="bXktc3VwZXItc2VjcmV0LXRva2Vu"
```

### cURL

You can also use the base64 encoded token with `curl`:

```bash
curl -H "Authorization: Bearer bXktc3VwZXItc2VjcmV0LXRva2Vu" http://my-verdaccio-registry.com/my-package
```

## Permissions

This plugin creates a JWT for the user with specific groups that you can use in the `packages` section of your `config.yaml` to define fine-grained permissions.

- If `readonly: true`, the user will be in the `ci-readonly` group.
- If `readonly: false`, the user will be in the `ci-readwrite` group.

You still need an `auth` plugin for Verdaccio to work. For example, you can use the default `htpasswd` plugin.

```yaml
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

## Author
Voodoo Gaming <https://www.voodoo.io>

## License
MIT
