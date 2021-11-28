import axios from "axios";
import jwkToPem from "jwk-to-pem";
import jwt from "jsonwebtoken";
import { Response } from "express";
import { cognitoJwtValidator, CognitoJwtValidatorRequest } from "..";

jest.mock("axios");
jest.mock("jwk-to-pem");
jest.mock("jsonwebtoken");
const testPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApjdss8ZaDfEH6K6U7GeW
2nxDqR4IP049fk1fK0lndimbMMVBdPv/hSpm8T8EtBDxrUdi1OHZfMhUixGaut+3
nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh+fKn9Fg++hS9UpazHpfVAFnB5aCf
XoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W/lsFCPGuzr4Vp0YS7zS2hDYSc
C2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y+vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLX
QsbKH1218/HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9/B/f1lVrmOKuHjTNHq4
8wIDAQAB
-----END PUBLIC KEY-----`;

describe("Validator", () => {
  const middleware = cognitoJwtValidator({
    region: "us-east-1",
    userPoolId: "user-pool-id-test",
    clientIds: ["https://test.com"],
    tokenUse: "access",
    jwtVerifyOptions: {
      algorithms: ["RS256"],
      ignoreExpiration: true,
    },
  });

  it("should skip empty auth header", async () => {
    const next = jest.fn();
    const req = { headers: {} } as CognitoJwtValidatorRequest;
    await middleware(req, {} as Response, next);

    expect(req.user).not.toBeDefined();
    expect(next.mock.calls.length).toBe(1);
    expect(next.mock.calls[0]).toEqual([]);
  });

  it("should skip non Bearer token", async () => {
    const next = jest.fn();
    const req = {
      headers: { authorization: "Basic test-token" },
    } as CognitoJwtValidatorRequest;
    await middleware(req, {} as Response, next);

    expect(req.user).not.toBeDefined();
    expect(next.mock.calls.length).toBe(1);
    expect(next.mock.calls[0]).toEqual([]);
  });

  it("should skip invalid JWT", async () => {
    const next = jest.fn();
    const req = {
      headers: {
        authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      },
    } as CognitoJwtValidatorRequest;
    await middleware(req, {} as Response, next);

    expect(req.user).not.toBeDefined();
    expect(next.mock.calls.length).toBe(1);
    expect(next.mock.calls[0]).toEqual([]);
  });

  it("should skip on decoded error", async () => {
    const next = jest.fn();
    const req = {
      headers: {
        authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      },
    } as CognitoJwtValidatorRequest;
    (jwt.decode as jest.Mock).mockImplementation(() => {
      throw new Error("invalid");
    });
    await middleware(req, {} as Response, next);

    expect(req.user).not.toBeDefined();
    expect(next.mock.calls.length).toBe(1);
    expect(next.mock.calls[0]).toEqual([]);
  });

  it("should skip JWT without kid", async () => {
    const next = jest.fn();
    const req = {
      headers: {
        authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      },
    } as CognitoJwtValidatorRequest;
    (jwt.decode as jest.Mock).mockImplementation(() => ({
      header: { kid: "test-kid" },
    }));
    await middleware(req, {} as Response, next);

    expect(req.user).not.toBeDefined();
    expect(next.mock.calls.length).toBe(1);
    expect(next.mock.calls[0]).toEqual([]);
  });

  it("should skip JWT without valid pem", async () => {
    const next = jest.fn();
    const req = {
      headers: {
        authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNjMzRjMGEwLWJkNWEtNGEzYy1hNTBkLWEyYTdkYjc2NDNkZiJ9.eyJzdWIiOiIxMjM0NTY3ODkiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE2MzgxMjA4Nzl9.ViWM5AQpRr2uXvIAvd-h9UUiUBwr9C8uPo0DUdk1g6I",
      },
    } as CognitoJwtValidatorRequest;
    (axios.get as jest.Mock).mockImplementation(() => ({
      data: { keys: [] },
    }));
    await middleware(req, {} as Response, next);

    expect(req.user).not.toBeDefined();
    expect(next.mock.calls.length).toBe(1);
    expect(next.mock.calls[0]).toEqual([]);
  });

  it("should skip invalid Cognito token use", async () => {
    const next = jest.fn();
    const req = {
      headers: {
        authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNjMzRjMGEwLWJkNWEtNGEzYy1hNTBkLWEyYTdkYjc2NDNkZiJ9.eyJzdWIiOiIxMjM0NTY3ODkiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE2MzgxMjA4Nzl9.ViWM5AQpRr2uXvIAvd-h9UUiUBwr9C8uPo0DUdk1g6I",
      },
    } as CognitoJwtValidatorRequest;
    (axios.get as jest.Mock).mockImplementation(() => ({
      data: { keys: [{ kid: "test-kid" }] },
    }));
    (jwkToPem as jest.Mock).mockImplementation(() => testPem);
    (jwt.verify as jest.Mock).mockImplementation(
      (token, secret, options, cb) => {
        cb(null, { token_use: "identity" });
      }
    );
    await middleware(req, {} as Response, next);

    expect(req.user).not.toBeDefined();
    expect(next.mock.calls.length).toBe(1);
    expect(next.mock.calls[0]).toEqual([]);
  });

  it("should skip JWT without valid pem", async () => {
    const next = jest.fn();
    const req = {
      headers: {
        authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNjMzRjMGEwLWJkNWEtNGEzYy1hNTBkLWEyYTdkYjc2NDNkZiJ9.eyJzdWIiOiIxMjM0NTY3ODkiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE2MzgxMjA4Nzl9.ViWM5AQpRr2uXvIAvd-h9UUiUBwr9C8uPo0DUdk1g6I",
      },
    } as CognitoJwtValidatorRequest;
    (axios.get as jest.Mock).mockImplementation(() => ({ data: { keys: [] } }));
    await middleware(req, {} as Response, next);

    expect(req.user).not.toBeDefined();
    expect(next.mock.calls.length).toBe(1);
    expect(next.mock.calls[0]).toEqual([]);
  });

  it("should skip invalid Cognito client_id", async () => {
    const next = jest.fn();
    const req = {
      headers: {
        authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNjMzRjMGEwLWJkNWEtNGEzYy1hNTBkLWEyYTdkYjc2NDNkZiJ9.eyJzdWIiOiIxMjM0NTY3ODkiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE2MzgxMjA4Nzl9.ViWM5AQpRr2uXvIAvd-h9UUiUBwr9C8uPo0DUdk1g6I",
      },
    } as CognitoJwtValidatorRequest;
    (axios.get as jest.Mock).mockImplementation(() => ({
      data: { keys: [{ kid: "test-kid" }] },
    }));
    (jwkToPem as jest.Mock).mockImplementation(() => testPem);
    (jwt.verify as jest.Mock).mockImplementation(
      (token, secret, options, cb) => {
        cb(null, { token_use: "access", client_id: "https://test.co" });
      }
    );
    await middleware(req, {} as Response, next);

    expect(req.user).not.toBeDefined();
    expect(next.mock.calls.length).toBe(1);
    expect(next.mock.calls[0]).toEqual([]);
  });

  it("should validate and add scopes", async () => {
    const next = jest.fn();
    (axios.get as jest.Mock).mockImplementation(() => ({
      data: { keys: [{ kid: "test-kid" }] },
    }));
    (jwkToPem as jest.Mock).mockImplementation(() => testPem);
    (jwt.verify as jest.Mock).mockImplementation(
      (token, secret, options, cb) => {
        cb(null, {
          token_use: "access",
          client_id: "https://test.com",
          scope: "user:create",
        });
      }
    );
    const req = {
      headers: {
        authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNjMzRjMGEwLWJkNWEtNGEzYy1hNTBkLWEyYTdkYjc2NDNkZiJ9.eyJzdWIiOiIxMjM0NTY3ODkiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE2MzgxMjA4Nzl9.ViWM5AQpRr2uXvIAvd-h9UUiUBwr9C8uPo0DUdk1g6I",
      },
    } as CognitoJwtValidatorRequest;
    await middleware(req, {} as Response, next);

    expect(next.mock.calls.length).toBe(1);
    expect(next.mock.calls[0]).toEqual([]);
    expect((req as any).user).toEqual(
      expect.objectContaining({
        token_use: "access",
        client_id: "https://test.com",
        scope: "user:create",
      })
    );
  });
});
