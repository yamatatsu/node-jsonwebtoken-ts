import { test, expect, describe } from "vitest";
import {
  typeError,
  checkIsPublicKey,
  checkIsPrivateKey,
  checkIsSecretKey,
  getAlgAndBits,
} from "../src/lib";

test("checkIsPublicKey", () => {
  expect(() => {
    checkIsPublicKey({
      type: "",
      asymmetricKeyType: "",
      export: "not-function",
    });
  }).toThrow(typeError("key must be a string or a buffer or a KeyObject"));
});

describe("checkIsPrivateKey()", () => {
  test.each([
    ["Buffer", Buffer.from("")],
    ["string", ""],
    ["object", {}],
  ])("if input is %s, no error is thrown.", (_, input) => {
    expect(checkIsPrivateKey(input)).toBeUndefined();
  });

  test("if input is number, error is thrown.", () => {
    expect(() => {
      checkIsPrivateKey(0);
    }).toThrow(typeError("key must be a string, a buffer or an object"));
  });
});

test("checkIsSecretKey", () => {
  expect(() => {
    checkIsSecretKey({ type: "", export: "not-function" });
  }).toThrow(typeError("secret must be a string or buffer or a KeyObject"));
});

test("getAlgAndBits", () => {
  expect(() => {
    getAlgAndBits("dummy-alg");
  }).toThrow(
    typeError(
      '"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".',
      "dummy-alg"
    )
  );
});
