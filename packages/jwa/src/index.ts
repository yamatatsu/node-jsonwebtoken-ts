// @ts-ignore
import bufferEqual from "buffer-equal-constant-time";
import { Buffer as SafeBuffer } from "safe-buffer";
import crypto from "crypto";
import formatEcdsa from "ecdsa-sig-formatter";
import { getAlgAndBits } from "./lib";

function createHmacSigner(bits: string) {
  return (
    thing: crypto.BinaryLike,
    secret: crypto.BinaryLike | crypto.KeyLike
  ) => {
    return crypto
      .createHmac("sha" + bits, secret)
      .update(thing)
      .digest("base64url");
  };
}

function createHmacVerifier(bits: string) {
  // TODO: allow signature to be BufferLike
  return (
    thing: crypto.BinaryLike,
    signature: string,
    secret: crypto.BinaryLike | crypto.KeyLike
  ) => {
    const computedSig = createHmacSigner(bits)(thing, secret);
    return bufferEqual(
      SafeBuffer.from(signature),
      SafeBuffer.from(computedSig)
    );
  };
}

function createKeySigner(bits: string) {
  return (
    thing: crypto.BinaryLike,
    privateKey:
      | crypto.KeyLike
      | crypto.SignKeyObjectInput
      | crypto.SignPrivateKeyInput
  ) => {
    // Even though we are specifying "RSA" here, this works with ECDSA
    // keys as well.
    return crypto
      .createSign("RSA-SHA" + bits)
      .update(thing)
      .sign(privateKey, "base64url");
  };
}

function createKeyVerifier(bits: string) {
  return (
    thing: crypto.BinaryLike,
    signature: string,
    publicKey:
      | crypto.KeyLike
      | crypto.VerifyKeyObjectInput
      | crypto.VerifyPublicKeyInput
  ) => {
    return crypto
      .createVerify("RSA-SHA" + bits)
      .update(thing)
      .verify(publicKey, signature, "base64url");
  };
}

function createPSSKeySigner(bits: string) {
  return (thing: crypto.BinaryLike, privateKey: string | Buffer) => {
    return crypto
      .createSign("RSA-SHA" + bits)
      .update(thing)
      .sign(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        },
        "base64url"
      );
  };
}

function createPSSKeyVerifier(bits: string) {
  return (
    thing: crypto.BinaryLike,
    signature: string,
    publicKey: string | Buffer
  ) => {
    return crypto
      .createVerify("RSA-SHA" + bits)
      .update(thing)
      .verify(
        {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        },
        signature,
        "base64url"
      );
  };
}

function createECDSASigner(bits: string) {
  const inner = createKeySigner(bits);
  return (
    thing: crypto.BinaryLike,
    secret:
      | crypto.KeyLike
      | crypto.SignKeyObjectInput
      | crypto.SignPrivateKeyInput
  ) => {
    return formatEcdsa.derToJose(inner(thing, secret), "ES" + bits);
  };
}

function createECDSAVerifier(bits: string) {
  const inner = createKeyVerifier(bits);
  return (
    thing: crypto.BinaryLike,
    signature: string,
    publicKey:
      | crypto.KeyLike
      | crypto.VerifyKeyObjectInput
      | crypto.VerifyPublicKeyInput
  ) => {
    signature = formatEcdsa
      .joseToDer(signature, "ES" + bits)
      .toString("base64");
    const result = inner(thing, signature, publicKey);
    return result;
  };
}

function createNoneSigner() {
  return () => "";
}

function createNoneVerifier() {
  return (_: any, signature: any) => signature === "";
}

type Algorithm =
  | "HS256"
  | "HS384"
  | "HS512"
  | "RS256"
  | "RS384"
  | "RS512"
  | "PS256"
  | "ES256"
  | "ES384"
  | "ES512"
  | "none";

export default function jwa(algorithm: Algorithm) {
  const signerFactories = {
    hs: createHmacSigner,
    rs: createKeySigner,
    ps: createPSSKeySigner,
    es: createECDSASigner,
    none: createNoneSigner,
  };
  const verifierFactories = {
    hs: createHmacVerifier,
    rs: createKeyVerifier,
    ps: createPSSKeyVerifier,
    es: createECDSAVerifier,
    none: createNoneVerifier,
  };
  const [algo, bits] = getAlgAndBits(algorithm);

  return {
    sign: signerFactories[algo](bits),
    verify: verifierFactories[algo](bits),
  };
}
