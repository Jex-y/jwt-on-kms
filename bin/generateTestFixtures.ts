import * as dotenv from 'dotenv';
dotenv.config();
import { KMSClient, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import fs from 'fs';
import path from 'path'
import { sign } from '../index';

const { KMS_KEY_ID, AWS_REGION } = process.env;

const payload = {
  hello: 'world',
}

const client = new KMSClient({
  region: AWS_REGION,
});

const publicKeyPromise = client.send(new GetPublicKeyCommand({
  KeyId: KMS_KEY_ID,
})).then((result) => result.PublicKey)


const now = new Date();

const normalTokenPromise = sign(payload, KMS_KEY_ID, { now: now.getTime() / 1000 });

const willExpireTokenPromise = sign(payload, KMS_KEY_ID, {
  expiresAt: new Date(now.getTime() - 5000),
  now: (now.getTime() / 1000) - 10,
});

const splitToken = (token: string) => {
  const [header, payload, signature] = token.split('.');
  return {
    header,
    payload,
    signature,
  };
}

Promise.all([publicKeyPromise, normalTokenPromise, willExpireTokenPromise]).then(([publicKey, normalToken, willExpireToken]) => {
  const json = JSON.stringify({
    now,
    payload,
    publicKey: Buffer.from(publicKey).toString('base64'),
    normalToken,
    normalTokenParts: splitToken(normalToken),
    willExpireToken,
    willExpireTokenParts: splitToken(willExpireToken),
  }, null, 2);

  console.log(json);

  fs.writeFileSync(path.resolve(__dirname, '../tests/fixtures.json'), json);
});