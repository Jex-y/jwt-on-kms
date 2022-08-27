# JWT on KMS

[![Node.js CI](https://github.com/Jex-y/jwt-on-kms/actions/workflows/test.yml/badge.svg)](https://github.com/Jex-y/jwt-on-kms/actions/workflows/test.yml)
[![Node.js Package](https://github.com/Jex-y/jwt-on-kms/actions/workflows/publish.yml/badge.svg)](https://github.com/Jex-y/jwt-on-kms/actions/workflows/publish.yml)

This package is designed to be able to verify JWT tokens offline by first downloading the public key from KMS. This is done to reduce latency and cost.

Example:

```ts
import JWTSigner from 'jwt-on-kms';
import { KMSClient } from '@aws-sdk/client-kms';

const kmsClient = new KMSClient({});

const { sign, verify } = new JWTSigner(kmsClient, process.env.KMS_KEY_ID);

const signedToken = sign({
  hello: 'world',
});

const { isValid } = verify(signedToken);
```
