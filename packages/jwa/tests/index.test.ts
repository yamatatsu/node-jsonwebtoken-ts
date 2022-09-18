import { test, expect } from "vitest";
import { readFileSync } from "fs";
import _jwa from "jwa";
import jwa from "../src";

const rsaPrivateKey = readFile("rsa.private.pem");
const rsaPublicKey = readFile("rsa.public.pem");
const pssPrivateKey = readFile("pss.private.pem");
const pssPublicKey = readFile("pss.public.pem");
const esPrivateKey = readFile("es.private.pem");
const esPublicKey = readFile("es.public.pem");

test.each([
  ["RS256", rsaPrivateKey, rsaPublicKey] as const,
  ["RS384", rsaPrivateKey, rsaPublicKey] as const,
  ["RS512", rsaPrivateKey, rsaPublicKey] as const,
  ["PS256", pssPrivateKey, pssPublicKey] as const,
  ["ES256", esPrivateKey, esPublicKey] as const,
  ["ES384", esPrivateKey, esPublicKey] as const,
  ["ES512", esPrivateKey, esPublicKey] as const,
  ["HS256", "secret", "secret"] as const,
])("sign() %s", (alg, signKey, verifyKey) => {
  const thing = "test-thing";
  const sig = jwa(alg).sign(thing, signKey);
  const valid = _jwa(alg).verify(thing, sig, verifyKey);
  expect(valid).toBe(true);
});

test.each([
  ["RS256", rsaPrivateKey, rsaPublicKey] as const,
  ["RS384", rsaPrivateKey, rsaPublicKey] as const,
  ["RS512", rsaPrivateKey, rsaPublicKey] as const,
  ["PS256", pssPrivateKey, pssPublicKey] as const,
  ["ES256", esPrivateKey, esPublicKey] as const,
  ["ES384", esPrivateKey, esPublicKey] as const,
  ["ES512", esPrivateKey, esPublicKey] as const,
  ["HS256", "secret", "secret"] as const,
])("verify() %s", (alg, signKey, verifyKey) => {
  const thing = "test-thing";
  const sig = _jwa(alg).sign(thing, signKey);
  const valid = jwa(alg).verify(thing, sig, verifyKey);
  expect(valid).toBe(true);
});

function readFile(fileName: string) {
  return readFileSync(`${__dirname}/keys/${fileName}`, "utf-8");
}
