// @ts-ignore
import bufferEqual from "buffer-equal-constant-time";
import { Buffer } from "safe-buffer";
import util from "util";

const MSG_INVALID_SECRET = "secret must be a string or buffer or a KeyObject";
const MSG_INVALID_VERIFIER_KEY =
  "key must be a string or a buffer or a KeyObject";
const MSG_INVALID_SIGNER_KEY = "key must be a string, a buffer or an object";
const MSG_INVALID_ALGORITHM =
  '"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".';

export function checkIsPublicKey(key: any) {
  if (Buffer.isBuffer(key)) return;
  if (typeof key === "string") return;

  if (
    typeof key !== "object" ||
    typeof key.type !== "string" ||
    typeof key.asymmetricKeyType !== "string" ||
    typeof key.export !== "function"
  ) {
    throw typeError(MSG_INVALID_VERIFIER_KEY);
  }
}

export function checkIsPrivateKey(key: any) {
  if (Buffer.isBuffer(key)) return;
  if (typeof key === "string") return;
  if (typeof key === "object") return;

  throw typeError(MSG_INVALID_SIGNER_KEY);
}

export function checkIsSecretKey(key: any) {
  if (Buffer.isBuffer(key)) return;
  if (typeof key === "string") return;

  if (
    typeof key !== "object" ||
    key.type !== "secret" ||
    typeof key.export !== "function"
  ) {
    throw typeError(MSG_INVALID_SECRET);
  }
}

export function getAlgAndBits(
  algorithm: string
): ["rs" | "ps" | "es" | "hs" | "none", string] {
  if (algorithm === "none") {
    return ["none", ""];
  }

  const match = algorithm.match(/^(RS|PS|ES|HS)(256|384|512)$|^(none)$/);
  if (!match) throw typeError(MSG_INVALID_ALGORITHM, algorithm);
  const algo = (match[1] || match[3]).toLowerCase() as
    | "rs"
    | "ps"
    | "es"
    | "hs"
    | "none";
  const bits = match[2];
  return [algo, bits];
}

export function typeError(template: string, ...args: any[]) {
  const errMsg = util.format(template, args);
  return new TypeError(errMsg);
}
