import { test, expect } from "vitest";
import { sign as _sign } from "jsonwebtoken";
import { sign } from "./sign";

test.each([
  [
    "secretOrPrivateKey must have a value",
    {},
    "",
    { algorithm: "RS256" } as const,
  ],
  [
    'Bad "options.expiresIn" option the payload already has an "exp" property.',
    { exp: 0 } as const,
    "key",
    { expiresIn: 0 } as const,
  ],
  [
    'Bad "options.notBefore" option the payload already has an "nbf" property.',
    { nbf: 0 } as const,
    "key",
    { notBefore: 0 } as const,
  ],
  [
    '"algorithm" must be a valid string enum value',
    { nbf: 0 } as const,
    "key",
    { algorithm: "dummy" as any } as const,
  ],
  [
    'Bad "options.audience" option. The payload already has an "aud" property.',
    { aud: "test-aud" } as const,
    "key",
    { audience: "test-aud" } as const,
  ],
])("%s", (error, payload, key, options) => {
  expect(() => {
    sign(payload, key, options);
  }).toThrowError(error);
});

test.each([
  ["specify payload.iat", { iat: 0 }, "key", undefined],
  ["specify option.noTimestamp", {}, "key", { noTimestamp: true } as const],
  ["specify option.notBefore", {}, "key", { notBefore: 0 } as const],
  ["specify option.expiresIn", {}, "key", { expiresIn: 0 } as const],
  ["specify option.audience", {}, "key", { audience: "test-aud" } as const],
  ["specify option.encoding", {}, "key", { encoding: "ascii" } as const],
])("%s", (_, payload, key, options) => {
  expect(sign(payload, key, options)).toBe(_sign(payload, key, options));
});
