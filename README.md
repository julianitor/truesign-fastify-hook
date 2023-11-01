<h1 align="center">Welcome to truesign-fastify-hook 👋</h1>
<p>
  <img alt="Version" src="https://img.shields.io/badge/version-1.0.0-blue.svg?cacheSeconds=2592000" />
  <a href="#" target="_blank">
    <img alt="License: ISC" src="https://img.shields.io/badge/License-ISC-yellow.svg" />
  </a>
  <a href="https://twitter.com/julipan37" target="_blank">
    <img alt="Twitter: julipan37" src="https://img.shields.io/twitter/follow/julipan37.svg?style=social" />
  </a>
</p>

This is a simple Fastify hook for handling requests with [Truesign](https://truesign.ai/) tokens on query string.

## Usage example
```js
import { getTruesignHook, TruesignHookConfig } from 'truesign-fastify-hook';

function shouldAcceptToken(
  decryptedToken: DecryptedToken, 
  config: TruesignHookConfig
): boolean {
  if (((Date.now() - decryptedToken.timestamp) / 1000) > config.tokenExpirationTimeSeconds) return false;
  return true;
}

const trueSignOptions: TruesignHookConfig = {
  shouldAcceptToken,
  encryptionKey: process.env.TRUESIGN_KEY,
  allowUnauthenticated: false,
  // we can add more configuration so we have this available in shouldAcceptToekn function
  tokenExpirationTimeSeconds: 30,
};

// when dealing with routes
fastify.addHook('onRequest', getTruesignHook(trueSignOptions));

// or in each secured route
fastify.route({
  method: 'GET',
  url: '/',
  schema: { ... },
  onRequest: getTruesignHook(trueSignOptions),
  // or
  preValidation: getTruesignHook(trueSignOptions),
  // or
  // or others
});

```

The decrypted token interface is a copy from [Truesign docs](https://my.truesign.ai/docs).

This is a simple package for a simple use case. If you want to extend it to more use cases, plese [contribute](./CONTRIBUTING.md)!

## Install

```sh
npm install
```

## Run tests

```sh
npm run test
```

## Author

👤 **Julian Toledo**

* Twitter: [@julipan37](https://twitter.com/julipan37)
* Github: [@julianitor](https://github.com/julianitor)

## Show your support

Give a ⭐️ if this project helped you!

***
_This README was generated with ❤️ by [readme-md-generator](https://github.com/kefranabg/readme-md-generator)_