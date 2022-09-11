import {
  KMSClient,
  GetPublicKeyCommand,
  SignCommand,
  SigningAlgorithmSpec,
  SignCommandOutput,
} from '@aws-sdk/client-kms';
import { webcrypto } from 'crypto';

const { subtle } = webcrypto;

export class JWTSigner {
  private client: KMSClient;
  private keyId: string;
  private localPublicKey: CryptoKey | null;

  constructor(kmsClient: KMSClient, keyId: string) {
    this.client = kmsClient;
    this.keyId = keyId;
  }

  private async getPublicKey(): Promise<CryptoKey> {
    if (this.localPublicKey) {
      return this.localPublicKey;
    }

    const params = {
      KeyId: this.keyId,
    };

    const result = await this.client.send(new GetPublicKeyCommand(params));

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

    this.localPublicKey = key;

    return key;
  }

  public async sign(
    payload: Record<string, unknown>,
    options?: {
      expiresIn?: number;
      expiresAt?: Date;
      algorithm?: SigningAlgorithmSpec;
      includeIat?: boolean;
      now?: number,
    }
  ): Promise<string> {
    const {
      algorithm = SigningAlgorithmSpec.RSASSA_PSS_SHA_256,
      includeIat = true,
      expiresIn,
      expiresAt,
    } = options || {};

    const headerString = JSON.stringify({
      alg: algorithm,
      typ: 'JWT',
    });

    const now = Math.floor(options?.now || (Date.now() / 1000));

    const payloadString = JSON.stringify({
      ...payload,
      ...(includeIat && { iat: now }),
      ...(expiresIn && { exp: now + expiresIn }),
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
      result = await this.client
        .send(
          new SignCommand({
            KeyId: this.keyId,
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

  public async verifyOffline(token: string): Promise<{
    payload?: Record<string, unknown>;
    error?: string;
    isValid: boolean;
  }> {
    const parts = token.split('.');

    const pubKeyPromise = this.getPublicKey();

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

    const result = await subtle.verify(
      {
        name: 'RSA-PSS',
        saltLength: 32,
      },
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
}
