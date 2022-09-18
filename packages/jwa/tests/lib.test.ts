import { test, expect } from "vitest";
import { typeError, getAlgAndBits } from "../src/lib";

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
