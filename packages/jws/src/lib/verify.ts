import { Buffer } from "safe-buffer";
// @ts-ignore
import jwa from "jwa";

const JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;

function safeJsonParse(thing: string) {
  try {
    return JSON.parse(thing);
  } catch (e) {
    return undefined;
  }
}

function headerFromJWS(jwsSig: string) {
  const encodedHeader = jwsSig.split(".", 1)[0];
  return safeJsonParse(Buffer.from(encodedHeader, "base64").toString("binary"));
}

function securedInputFromJWS(jwsSig: string) {
  return jwsSig.split(".", 2).join(".");
}

function signatureFromJWS(jwsSig: string) {
  return jwsSig.split(".")[2];
}

function payloadFromJWS(jwsSig: string, encoding: string = "utf8") {
  const payload = jwsSig.split(".")[1];
  return Buffer.from(payload, "base64").toString(encoding);
}

export function isValid(str: string) {
  return JWS_REGEX.test(str) && !!headerFromJWS(str);
}

export function verify(jwsSig: string, algorithm: any, secretOrKey: any) {
  if (!algorithm) {
    const err: Error & { code?: string } = new Error(
      "Missing algorithm parameter for jws.verify"
    );
    err.code = "MISSING_ALGORITHM";
    throw err;
  }

  const signature = signatureFromJWS(jwsSig);
  const securedInput = securedInputFromJWS(jwsSig);
  const algo = jwa(algorithm);
  return algo.verify(securedInput, signature, secretOrKey);
}

type Oprions = {
  json?: boolean;
  encoding?: string;
};
export function decode(jwsSig: string, opts: Oprions = {}) {
  if (!isValid(jwsSig)) return null;

  const header = headerFromJWS(jwsSig);

  if (!header) return null;

  const payload = payloadFromJWS(jwsSig);

  return {
    header: header,
    payload: header.typ === "JWT" || opts.json ? JSON.parse(payload) : payload,
    signature: signatureFromJWS(jwsSig),
  };
}
