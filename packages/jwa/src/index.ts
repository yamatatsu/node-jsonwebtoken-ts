// @ts-ignore
import bufferEqual from "buffer-equal-constant-time";
import { Buffer } from "safe-buffer";
import crypto from "crypto";
import formatEcdsa from "ecdsa-sig-formatter";
import {
  checkIsPublicKey,
  checkIsPrivateKey,
  checkIsSecretKey,
  getAlgAndBits,
} from "./lib";

type Sign = (thing: string, secret: any) => string;
type Verify = (thing: string, signature: string, secret: any) => boolean;

function createHmacSigner(bits: string): Sign {
  return (thing, secret) => {
    checkIsSecretKey(secret);

    return crypto
      .createHmac("sha" + bits, secret)
      .update(thing)
      .digest("base64url");
  };
}

function createHmacVerifier(bits: string): Verify {
  return (thing, signature, secret) => {
    const computedSig = createHmacSigner(bits)(thing, secret);
    return bufferEqual(Buffer.from(signature), Buffer.from(computedSig));
  };
}

function createKeySigner(bits: string): Sign {
  return (thing, privateKey) => {
    checkIsPrivateKey(privateKey);

    // Even though we are specifying "RSA" here, this works with ECDSA
    // keys as well.
    return crypto
      .createSign("RSA-SHA" + bits)
      .update(thing)
      .sign(privateKey, "base64url");
  };
}

function createKeyVerifier(bits: string): Verify {
  return (thing, signature, publicKey) => {
    checkIsPublicKey(publicKey);

    return crypto
      .createVerify("RSA-SHA" + bits)
      .update(thing)
      .verify(publicKey, signature, "base64url");
  };
}

function createPSSKeySigner(bits: string): Sign {
  return (thing, privateKey) => {
    checkIsPrivateKey(privateKey);

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

function createPSSKeyVerifier(bits: string): Verify {
  return (thing, signature, publicKey) => {
    checkIsPublicKey(publicKey);

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

function createECDSASigner(bits: string): Sign {
  const inner = createKeySigner(bits);
  return (thing, secret) => {
    return formatEcdsa.derToJose(inner(thing, secret), "ES" + bits);
  };
}

function createECDSAVerifier(bits: string): Verify {
  const inner = createKeyVerifier(bits);
  return (thing, signature, publicKey) => {
    signature = formatEcdsa
      .joseToDer(signature, "ES" + bits)
      .toString("base64");
    const result = inner(thing, signature, publicKey);
    return result;
  };
}

function createNoneSigner(): Sign {
  return () => "";
}

function createNoneVerifier(): Verify {
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
