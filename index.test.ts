import JWTSigner from "./index";
import { KMSClient, SignCommand } from "@aws-sdk/client-kms";
import { mockClient } from "aws-sdk-client-mock";

const mock = mockClient(KMSClient);

const client = new KMSClient({
  region: "DEV",
});

describe("JWTSigner", () => {
  beforeEach(() => {
    mock.reset();
  });

  it("should call the signCommand correctly", async () => {
    const keyId = "keyId";

    mock
      .on(SignCommand, {
        KeyId: keyId,
        SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
      })
      .resolves({
        Signature: Buffer.from("hello world"),
      });

    const jwtSigner = new JWTSigner(client, "keyId");
    const signature = await jwtSigner.sign({
      hello: "world",
    });
    expect(signature).toBeTruthy();
  });

  it("should throw an error if the key is not found", async () => {
    const keyId = "keyId";

    mock
      .on(SignCommand, {
        KeyId: keyId,
        SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
      })
      .rejects("A very long error message");

    const jwtSigner = new JWTSigner(client, "keyId");
    await expect(
      jwtSigner.sign({
        hello: "world",
      })
    ).rejects.toThrow("Failed to sign the payload");
  });
});
