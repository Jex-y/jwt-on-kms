import { JWTSigner } from '../index';
import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
} from '@aws-sdk/client-kms';
import { mockClient } from 'aws-sdk-client-mock';
import { PUBLIC_KEY, NORMAL, EXPIRES_IN } from './test_constants';

jest.useFakeTimers().setSystemTime(new Date('2020-01-01T00:00:00.000Z'));

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
      Signature: NORMAL.SIGNATURE,
    });

    const jwtSigner = new JWTSigner(client, 'keyId');
    const token = await jwtSigner.sign(NORMAL.PAYLOAD);

    expect(mock).toHaveReceivedCommandWith(SignCommand, {
      KeyId: 'keyId',
      SigningAlgorithm: 'RSASSA_PSS_SHA_256',
      Message: Buffer.from(NORMAL.HEADER_AND_PAYLOAD),
    });

    expect(token).toBe(NORMAL.FULL_TOKEN);
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
      PublicKey: PUBLIC_KEY,
    });

    const jwtSigner = new JWTSigner(client, 'keyId');
    const payload = await jwtSigner.verifyOffline(NORMAL.FULL_TOKEN);

    expect(payload).toStrictEqual({
      payload: NORMAL.PAYLOAD,
      isValid: true,
    });

    expect(mock).toHaveReceivedCommandWith(GetPublicKeyCommand, {
      KeyId: 'keyId',
    });
  });

  it('should only fetch the public key once', async () => {
    mock.on(GetPublicKeyCommand).resolves({
      PublicKey: PUBLIC_KEY,
    });

    const jwtSigner = new JWTSigner(client, 'keyId');
    await jwtSigner.verifyOffline(NORMAL.FULL_TOKEN);
    await jwtSigner.verifyOffline(NORMAL.FULL_TOKEN);

    expect(mock).toHaveReceivedCommandWith(GetPublicKeyCommand, {
      KeyId: 'keyId',
    });

    expect(mock.call).toHaveLength(1);
  });

  it('should return an error if the token is invalid', async () => {
    mock.on(GetPublicKeyCommand).resolves({
      PublicKey: PUBLIC_KEY,
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
      PublicKey: PUBLIC_KEY,
    });

    const jwtSigner = new JWTSigner(client, 'keyId');
    await expect(
      jwtSigner.verifyOffline(NORMAL.HEADER_AND_PAYLOAD + EXPIRES_IN.SIGNATURE)
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
    const token = await jwtSigner.sign(EXPIRES_IN.PAYLOAD, {
      expiresIn: 1,
    });

    const payload = JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString()
    );

    expect(payload.exp).toStrictEqual(new Date().getTime() / 1000 + 1);
  });

  it('should return an error if the token is expired', async () => {
    jest.setSystemTime(new Date('2020-01-01T01:00:00.000Z'));
    mock.on(GetPublicKeyCommand).resolves({
      PublicKey: PUBLIC_KEY,
    });

    const jwtSigner = new JWTSigner(client, 'keyId');
    await expect(
      jwtSigner.verifyOffline(EXPIRES_IN.FULL_TOKEN)
    ).resolves.toStrictEqual({
      payload: { ...EXPIRES_IN.PAYLOAD, exp: 1577836801 },
      error: 'Token expired',
      isValid: false,
    });
  });
});
