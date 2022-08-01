import {
  KMSClient,
  GetPublicKeyCommand,
  SignCommand,
  SigningAlgorithmSpec,
} from "@aws-sdk/client-kms";
import NodeRSA from "node-rsa";

class JWTSigner {
  private client: KMSClient;
  private keyId: string;
  private localPublicKey: NodeRSA | null;

  constructor(kmsClient: KMSClient, keyId: string) {
    this.client = kmsClient;
    this.keyId = keyId;
  }

  private async getPublicKey(): Promise<NodeRSA> {
    if (this.localPublicKey) {
      return this.localPublicKey;
    }

    const params = {
      KeyId: this.keyId,
    };

    const result = await this.client.send(new GetPublicKeyCommand(params));

    if (!result.PublicKey) {
      throw new Error("No key found");
    }

    const key = new NodeRSA();

    key.importKey(Buffer.from(result.PublicKey), "pkcs8-public-der");

    if (!key) {
      throw new Error("Invalid key recieved");
    }

    this.localPublicKey = key;

    return key;
  }

  public async sign(
    payload: Record<string, unknown>,
    algo: SigningAlgorithmSpec = SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256
  ): Promise<string> {
    const headerString = JSON.stringify({
      alg: algo,
      typ: "JWT",
    });

    const payloadString = JSON.stringify(payload);

    const messageBuffer = Buffer.from(`${headerString}.${payloadString}`);

    if (messageBuffer.length > 4096) {
      throw new Error("Message must be less than 4096 bytes");
    }

    const result = await this.client
      .send(
        new SignCommand({
          KeyId: this.keyId,
          Message: messageBuffer,
          SigningAlgorithm: algo,
        })
      )
      .catch((err) => {
        console.error(err);
        throw new Error("Failed to sign the payload");
      });

    if (!result.Signature) {
      console.error("No signature found on SignCommand result");
      throw new Error("Failed to sign the payload");
    }

    const headerEncoded = Buffer.from(headerString).toString("base64url");
    const payloadEncoded = Buffer.from(payloadString).toString("base64url");
    const signatureEncoded = Buffer.from(result.Signature).toString(
      "base64url"
    );
    return `${headerEncoded}.${payloadEncoded}.${signatureEncoded}`;
  }

  public async verifyOffline(token: string): Promise<Record<string, unknown>> {
    const parts = token.split(".");

    const pubKeyPromise = this.getPublicKey();

    if (parts.length !== 3) {
      throw new Error("Invalid token");
    }

    const headerString = Buffer.from(parts[0], "base64url").toString();
    const payloadString = Buffer.from(parts[1], "base64url").toString();
    const signatureString = Buffer.from(parts[2], "base64url");

    const message = `${headerString}.${payloadString}`;

    const result = (await pubKeyPromise).verify(message, signatureString);

    if (result) {
      return {
        header: JSON.parse(headerString),
        payload: JSON.parse(payloadString),
      };
    } else {
      throw new Error("Invalid token");
    }
  }
}

export default JWTSigner;
