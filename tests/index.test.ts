import { JWTSigner } from '../index';
import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
} from '@aws-sdk/client-kms';
import { mockClient } from 'aws-sdk-client-mock';
// import { PUBLIC_KEY, NORMAL, EXPIRES_IN } from './test_constants'
import fs from 'fs';
import path from 'path';

type tokenParts = {
  header: string,
  payload: string,
  signature: string,
}

let fixtures;

try {
  fixtures = JSON.parse(fs.readFileSync(path.resolve(__dirname, 'fixtures.json')).toString());
} catch {
  throw new Error('Fixtures not generated, run yarn generate-fixtures');
}

const {
  now,
  payload,
  publicKey,
  normalToken,
  normalTokenParts,
  willExpireToken,
  willExpireTokenParts,
}: {
  now: string,
  payload: Record<string, unknown>,
  publicKey: string,
  normalToken: string,
  normalTokenParts: tokenParts,
  willExpireToken: string,
  willExpireTokenParts: tokenParts,
} = fixtures

const publicKeyBuffer = Buffer.from(publicKey, 'base64');

jest.useFakeTimers().setSystemTime(new Date(now));

const mock = mockClient(KMSClient);

const client = new KMSClient({
  region: 'DEV',
});

describe('JWTSigner', () => {
  beforeEach(() => {
    mock.reset();
  });

  it('should return the correctly signed token', async () => {
    mock.on(SignCommand).resolves({
      Signature: Buffer.from(normalTokenParts.signature, 'base64'),
    });

    const jwtSigner = new JWTSigner(client, 'keyId');
    const token = await jwtSigner.sign(payload);

    expect(mock).toHaveReceivedCommandWith(SignCommand, {
      KeyId: 'keyId',
      SigningAlgorithm: 'RSASSA_PSS_SHA_256',
      Message: Buffer.from(`${normalTokenParts.header}.${normalTokenParts.payload}`),
    });

    expect(token).toBe(normalToken);
  });

  it('should throw an error if the key is not found', async () => {
    const keyId = 'keyId';

    mock
      .on(SignCommand, {
        KeyId: keyId,
      })
      .rejects('A very long error message');

    const jwtSigner = new JWTSigner(client, 'keyId');
    await expect(
      jwtSigner.sign({
        hello: 'world',
      })
    ).rejects.toThrow('Failed to sign the payload');
  });

  it('should correcly validate and decode a token', async () => {
    mock.on(GetPublicKeyCommand).resolves({
      PublicKey: publicKeyBuffer,
    });

    const jwtSigner = new JWTSigner(client, 'keyId');
    const result = await jwtSigner.verifyOffline(normalToken);

    expect(result).toStrictEqual({
      payload: {
        ...payload,
        iat: Math.floor(Date.now() / 1000),
      },
      isValid: true,
    });

    expect(mock).toHaveReceivedCommandWith(GetPublicKeyCommand, {
      KeyId: 'keyId',
    });
  });

  it('should only fetch the public key once', async () => {
    mock.on(GetPublicKeyCommand).resolves({
      PublicKey: publicKeyBuffer,
    });

    const jwtSigner = new JWTSigner(client, 'keyId');
    await jwtSigner.verifyOffline(normalToken);
    await jwtSigner.verifyOffline(normalToken);

    expect(mock).toHaveReceivedCommandWith(GetPublicKeyCommand, {
      KeyId: 'keyId',
    });

    expect(mock.call).toHaveLength(1);
  });

  it('should return an error if the token is invalid', async () => {
    mock.on(GetPublicKeyCommand).resolves({
      PublicKey: publicKeyBuffer,
    });

    const jwtSigner = new JWTSigner(client, 'keyId');
    await expect(
      jwtSigner.verifyOffline('invalid token')
    ).resolves.toStrictEqual({
      error: 'Invalid token',
      isValid: false,
    });
  });

  it('should return an error if the signature is invalid', async () => {
    mock.on(GetPublicKeyCommand).resolves({
      PublicKey: publicKeyBuffer,
    });

    const jwtSigner = new JWTSigner(client, 'keyId');
    await expect(
      jwtSigner.verifyOffline(`${normalTokenParts.header}.${normalTokenParts.payload}.${willExpireTokenParts.signature}`)
    ).resolves.toStrictEqual({
      error: 'Invalid signature',
      isValid: false,
    });
  });

  it('should sign a token that exires in some time', async () => {
    mock.on(SignCommand).resolves({
      Signature: Buffer.from('A signature'),
    });

    const jwtSigner = new JWTSigner(client, 'keyId');
    const token = await jwtSigner.sign(payload, {
      expiresIn: 1,
    });

    const recievedPayload = JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString()
    );

    expect(recievedPayload.exp).toStrictEqual(Math.floor(new Date().getTime() / 1000 + 1));
  });

  it('should return an error if the token is expired', async () => {
    mock.on(GetPublicKeyCommand).resolves({
      PublicKey: publicKeyBuffer,
    });

    const jwtSigner = new JWTSigner(client, 'keyId');
    await expect(
      jwtSigner.verifyOffline(willExpireToken)
    ).resolves.toStrictEqual({
      payload: { ...payload, exp: Math.floor(Date.now() / 1000) - 5, iat: Math.floor(Date.now() / 1000) - 10 },
      error: 'Token expired',
      isValid: false,

    });
  });

  it('should not inlcude iat if includeIat is false', async () => {
    mock.on(SignCommand).resolves({
      Signature: Buffer.from('A signature'),
    });

    const jwtSigner = new JWTSigner(client, 'keyId');
    const token = await jwtSigner.sign(payload, {
      includeIat: false,
    });

    const recievedPayload = JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString()
    );

    expect(recievedPayload.iat).toBeUndefined();

  })
});
