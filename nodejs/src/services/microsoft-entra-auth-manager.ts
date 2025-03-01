import jwt from "jsonwebtoken";
import JWKSClient from "jwks-rsa";

// These values should env variables
const MICROSOFT_ENTRA_AUDIENCE = "my-audience";
const MICROSOFT_ENTRA_JWKS_URI =
  "https://login.microsoftonline.com/c8ggje2c-efc5-4bg4-bdde-df81fab36d55/discovery/v2.0/keys";
const MICROSOFT_ENTRA_TOKEN_ISSUER =
  "https://login.microsoftonline.com/cksi854s-efc5-4be4-paoj-df81fab36d42/v2.0";

export type AuthTokenData =
  | {
      [key: string]: any;
    }
  | string;

const client = JWKSClient({
  jwksUri: MICROSOFT_ENTRA_JWKS_URI,
});

function getPublicKey(token: string): Promise<JWKSClient.SigningKey> {
  const decoded = jwt.decode(token, { complete: true });
  return client.getSigningKey(decoded?.header.kid);
}

export class MicrosoftEntraAuthManager {
  async parseToken(token: string): Promise<AuthTokenData> {
    try {
      const publicKey = await getPublicKey(token);
      return jwt.verify(token, publicKey.getPublicKey(), {
        audience: MICROSOFT_ENTRA_AUDIENCE,
        issuer: MICROSOFT_ENTRA_TOKEN_ISSUER,
      });
    } catch (err) {
      throw err;
    }
  }

  createToken(data: AuthTokenData): string {
    return "";
  }
}
