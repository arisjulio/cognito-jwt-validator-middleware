import jwt from "jsonwebtoken";
import { KeyValueCache, JwkCache } from "./lib/jwkCache";
import { Options as CacheOptions } from "node-cache";
import { JwkParser } from "./lib/jwkParser";
import { Request, Response, NextFunction } from "express";
import { promisify } from "util";

interface CognitoJwtValidatorOptions {
  region: string;
  userPoolId: string;
  clientIds: string[];
  tokenUse: "access" | "id";
  jwtVerifyOptions?: jwt.VerifyOptions;
  cache?: {
    keyValueCache?: KeyValueCache;
    options?: CacheOptions;
  };
}

export interface CognitoJwtPayload extends jwt.JwtPayload {
  // eslint-disable-next-line camelcase
  token_use: string;
  // eslint-disable-next-line camelcase
  event_id: string;
  scope: string;
  // eslint-disable-next-line camelcase
  auth_time: number;
  version: number;
  // eslint-disable-next-line camelcase
  client_id: string;
  username: string;
}

const verifyToken = promisify<
  string,
  jwt.Secret,
  jwt.VerifyOptions,
  CognitoJwtPayload
>(jwt.verify);

export interface CognitoJwtValidatorRequest extends Request {
  user: CognitoJwtPayload;
}

type CognitoJwtValidatorRequestHandler = (
  req: CognitoJwtValidatorRequest,
  res: Response,
  next: NextFunction
) => Promise<void>;

export const cognitoJwtValidator = (
  options: CognitoJwtValidatorOptions
): CognitoJwtValidatorRequestHandler => {
  const cache =
    options.cache?.keyValueCache ?? new JwkCache(options.cache?.options);
  const parser = new JwkParser(cache, options.region, options.userPoolId);

  return async (req, res, next) => {
    try {
      if (!req.headers.authorization) return next();
      const tokenParts = req.headers.authorization.split(" ");
      if (tokenParts[0] !== "Bearer") return next();

      const decoded = jwt.decode(tokenParts[1], { complete: true });
      if (!decoded || !decoded.header.kid) return next();

      const pem = await parser.getPem(decoded.header.kid);
      if (!pem) return next();

      const verifyOptions = options.jwtVerifyOptions ?? {
        algorithms: ["RS256"],
        ignoreExpiration: false,
      };
      const verified = await verifyToken(tokenParts[1], pem, verifyOptions);
      if (verified.token_use !== options.tokenUse) return next();
      if (!options.clientIds.includes(verified.client_id)) return next();

      req.user = { ...verified };
      next();
    } catch (err) {
      next();
    }
  };
};
