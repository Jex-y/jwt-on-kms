# JWT on KMS

[![Tests](https://github.com/Jex-y/jwt-on-kms/actions/workflows/publish.yml/badge.svg)](https://github.com/Jex-y/jwt-on-kms/actions/workflows/publish.yml)

This package is designed to be able to verify JWT tokens offline by first downloading the public key from KMS. This is done to reduce latency and cost.

## Usage

```ts
import { sign, verify } from 'jwt-on-kms';
import { KMSClient } from '@aws-sdk/client-kms';

const signedToken = sign(
  {
    hello: 'world',
  },
  kmsKeyId
);

const { isValid } = verify(signedToken, kmsKeyId);
```

To use a custom client / use client options call `setClient(yourClient)`.

## Testing

To generate test fixtures, you need to create a KMS key in your AWS account that allows signing and verification with `RSASSA_PSS_SHA_256`. Set the `KMS_KEY_ID` environment variable to the ID of the key and `AWS_REGION` to region the key is in. Then run `yarn generate-fixtures` and then `yarn test`.

## Bugs

If you find a security vulnerability, please report it privately to me via [email](mailto:edwardjex@live.co.uk). Other bugs should be reported via GitHub.
