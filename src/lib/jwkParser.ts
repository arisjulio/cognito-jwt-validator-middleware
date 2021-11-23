import jwt from "jsonwebtoken";
import Debug from "debug";
import jwkToPem from "jwk-to-pem";
import axios from "axios";
import { KeyValueCache } from "./jwkCache";

const debug = Debug("cognito-jwt-validator-middleware:jwk-parser");

export class JwkParser {
  /** Cache object */
  private readonly cache: KeyValueCache;
  /** AWS region to download JWK */
  private readonly region: string;
  /** AWS Cognito user pool id to download JWK */
  private readonly userPoolId: string;

  constructor(cache: KeyValueCache, region: string, userPoolId: string) {
    this.cache = cache;
    this.region = region;
    this.userPoolId = userPoolId;
  }

  /**
   * Download the JWK for the given key ID and returns a PEM to use as secret to
   * verify a JWT.
   *
   * @param kid JWT key ID
   * @returns PEM to use as JWT secret
   */
  async getPem(kid: string): Promise<jwt.Secret | undefined> {
    try {
      const cachedPem = await this.cache.get<jwt.Secret>(kid);
      if (cachedPem) return cachedPem;

      const response = await axios.get(
        `https://cognito-idp.${this.region}.amazonaws.com/${this.userPoolId}/.well-known/jwks.json`
      );
      const jwk = response.data.keys.filter((v: any) => v.kid === kid)[0];
      const pem = jwkToPem(jwk);
      await this.cache.set(kid, pem);
      return pem;
    } catch (err) {
      debug("Can not get pem", err);
    }
  }
}
