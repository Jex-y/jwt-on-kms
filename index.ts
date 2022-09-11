import {
  KMSClient,
  GetPublicKeyCommand,
  SignCommand,
  SigningAlgorithmSpec,
  SignCommandOutput,
} from '@aws-sdk/client-kms';
import { webcrypto } from 'crypto';

const { subtle } = webcrypto;

let client;

const pubKeyCache = {};

export const setClient = (newClient: KMSClient) => {
  client = newClient;
};

const getClient = (): KMSClient => {
  if (!client) {
    client = new KMSClient({});
  }
  return client;
}

const getPublicKey = async (keyId: string): Promise<CryptoKey> => {
  if (pubKeyCache[keyId]) {
    return pubKeyCache[keyId];
  }

  const result = await getClient().send(new GetPublicKeyCommand({ KeyId: keyId }));

  if (!result.PublicKey) {
    throw new Error('No key found');
  }

  const key = await subtle.importKey(
    'spki',
    Buffer.from(result.PublicKey),
    {
      name: 'RSA-PSS',
      hash: { name: 'SHA-256' },
    },
    true,
    ['verify']
  );

  if (!key) {
    throw new Error('Invalid key recieved');
  }

  pubKeyCache[keyId] = key;

  return key;

}

export const sign = async (payload: object, keyId: string, options?: {
  expiresIn?: number;
  expiresAt?: Date;
  algorithm?: SigningAlgorithmSpec;
  includeIat?: boolean;
  now?: number,
}): Promise<string> => {
  const {
    algorithm = SigningAlgorithmSpec.RSASSA_PSS_SHA_256,
    includeIat = true,
    expiresIn,
    expiresAt,
    now = Date.now() / 1000,
  } = options || {};

  const headerString = JSON.stringify({
    alg: algorithm,
    typ: 'JWT',
  });

  const payloadString = JSON.stringify({
    ...payload,
    ...(includeIat && { iat: Math.floor(now) }),
    ...(expiresIn && { exp: Math.floor(now + expiresIn) }),
    ...(expiresAt && { exp: Math.floor(expiresAt.getTime() / 1000) }),
  });

  const headerEncoded = Buffer.from(headerString).toString('base64url');
  const payloadEncoded = Buffer.from(payloadString).toString('base64url');

  const messageBuffer = Buffer.from(`${headerEncoded}.${payloadEncoded}`);

  if (messageBuffer.length > 4096) {
    throw new Error('Message must be less than 4096 bytes');
  }

  let result: SignCommandOutput;

  try {
    console.log(messageBuffer.toString());
    result = await getClient().send(

      new SignCommand({
        KeyId: keyId,
        Message: messageBuffer,
        SigningAlgorithm: algorithm,
      })
    )

  } catch (err) {
    console.warn(err);
    throw new Error('Failed to sign the payload');
  };

  if (!result?.Signature) {
    throw new Error('Failed to sign the payload');
  }

  const signatureEncoded = Buffer.from(result.Signature).toString(
    'base64url'
  );

  return `${headerEncoded}.${payloadEncoded}.${signatureEncoded}`;
}

export const verify = async (token: string, keyId: string, options?: {
  algorithm?: SigningAlgorithmSpec,
  now?: number,
}): Promise<{
  payload?: Record<string, unknown>;
  error?: string;
  isValid: boolean;
}> => {

  const { algorithm = SigningAlgorithmSpec.RSASSA_PSS_SHA_256, now = Math.floor(Date.now() / 1000) } = options || {};

  const parts = token.split('.');

  const pubKeyPromise = getPublicKey(keyId);

  if (parts.length !== 3) {
    return {
      isValid: false,
      error: 'Invalid token',
    };
  }

  const headerString = parts[0];
  const payloadString = parts[1];
  const signatureString = Buffer.from(parts[2], 'base64url');

  const message = `${headerString}.${payloadString}`;

  const algo = verifyAlgorithmMap[algorithm];

  if (!algo) {
    return {
      isValid: false,
      error: 'Unsupported algorithm',
    };
  }

  const result = await subtle.verify(
    algo,
    await pubKeyPromise,
    signatureString,
    Buffer.from(message)
  );

  if (!result) {
    return {
      isValid: false,
      error: 'Invalid signature',
    };
  }

  let payload;

  try {
    payload = JSON.parse(Buffer.from(payloadString, 'base64url').toString());
  } catch (err) {
    console.warn(err);
    return {
      isValid: false,
      error: 'Invalid payload',
    };
  }

  if (payload.exp) {
    const now = new Date().getTime() / 1000;
    if (payload.exp < now) {
      return {
        isValid: false,
        error: 'Token expired',
        payload,
      };
    }
  }

  return {
    isValid: true,
    payload,
  };
}

const verifyAlgorithmMap: Record<SigningAlgorithmSpec, webcrypto.AlgorithmIdentifier | webcrypto.RsaPssParams | webcrypto.EcdsaParams | webcrypto.Ed448Params> = {
  [SigningAlgorithmSpec.RSASSA_PSS_SHA_256]: { name: 'RSA-PSS', saltLength: 32 },
  [SigningAlgorithmSpec.RSASSA_PSS_SHA_384]: { name: 'RSA-PSS', saltLength: 48 },
  [SigningAlgorithmSpec.RSASSA_PSS_SHA_512]: { name: 'RSA-PSS', saltLength: 64 },
  [SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256]: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
  [SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384]: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-384' } },
  [SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512]: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-512' } },
  [SigningAlgorithmSpec.ECDSA_SHA_256]: undefined,
  [SigningAlgorithmSpec.ECDSA_SHA_384]: undefined,
  [SigningAlgorithmSpec.ECDSA_SHA_512]: undefined,
  [SigningAlgorithmSpec.SM2DSA]: undefined,
};

