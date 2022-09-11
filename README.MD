# JWT on KMS

[![Node.js CI](https://github.com/Jex-y/jwt-on-kms/actions/workflows/test.yml/badge.svg)](https://github.com/Jex-y/jwt-on-kms/actions/workflows/test.yml)
[![Node.js Package](https://github.com/Jex-y/jwt-on-kms/actions/workflows/publish.yml/badge.svg)](https://github.com/Jex-y/jwt-on-kms/actions/workflows/publish.yml)

This package is designed to be able to verify JWT tokens offline by first downloading the public key from KMS. This is done to reduce latency and cost.

## Usage

```ts
import { JWTSigner } from 'jwt-on-kms';
import { KMSClient } from '@aws-sdk/client-kms';

const kmsClient = new KMSClient({});

const { sign, verifyOffline } = new JWTSigner(
  kmsClient,
  process.env.KMS_KEY_ID
);

const signedToken = sign({
  hello: 'world',
});

const { isValid } = verifyOffline(signedToken);
```

## Testing

To generate test fixtures, you need to create a KMS key in your AWS account that allows signing and verification with `RSASSA_PSS_SHA_256`. Set the `KMS_KEY_ID` environment variable to the ID of the key and `AWS_REGION` to region the key is in. Then run `yarn generate-fixtures` and then `yarn test`.

## Bugs

If you find a security vulnerability, please report it privately to me via [email](mailto:edwardjex@live.co.uk). Other bugs should be reported via GitHub.
