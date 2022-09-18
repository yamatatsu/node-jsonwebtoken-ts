import { test, expect } from "vitest";
import { sign as _sign, decode as _decode } from "jsonwebtoken";
import { verify } from "./verify";
import { JsonWebTokenError } from "./lib/JsonWebTokenError";
import { NotBeforeError } from "./lib/NotBeforeError";
import { TokenExpiredError } from "./lib/TokenExpiredError";

test.each([
  [
    new JsonWebTokenError("nonce must be a non-empty string"),
    "dummy-token",
    "key",
    { nonce: " " },
  ],
  [new JsonWebTokenError("jwt malformed"), "a.b.c.d", "key", {}],
  [new JsonWebTokenError("invalid token"), "a.b.c", "key", {}],
  [
    new JsonWebTokenError("jwt signature is required"),
    _sign({}, "key").replace(/\.[\w\d-]*$/, "."),
    "key",
    {},
  ],
  [
    new JsonWebTokenError("secret or public key must be provided"),
    _sign({}, "key"),
    "",
    {},
  ],
  [
    new JsonWebTokenError("invalid algorithm"),
    _sign({}, "key"),
    "key",
    { algorithms: [] },
  ],
  [
    new JsonWebTokenError("invalid signature"),
    _sign({}, "key").replace(/.$/, ""),
    "key",
    {},
  ],
  [
    new NotBeforeError("jwt not active", new Date()),
    _sign({ nbf: now() + 10 }, "key"),
    "key",
    {},
  ],
  [
    new TokenExpiredError("jwt expired", new Date()),
    _sign({ exp: now() - 10 }, "key"),
    "key",
    {},
  ],
  [
    new JsonWebTokenError("jwt audience invalid. expected: foo or /^bar\\d$/"),
    _sign({}, "key"),
    "key",
    { audience: ["foo", /^bar\d$/] },
  ],
  [
    new JsonWebTokenError("jwt issuer invalid. expected: foo"),
    _sign({}, "key"),
    "key",
    { issuer: "foo" },
  ],
  [
    new JsonWebTokenError("jwt subject invalid. expected: foo"),
    _sign({}, "key"),
    "key",
    { subject: "foo" },
  ],
  [
    new JsonWebTokenError("jwt jwtid invalid. expected: foo"),
    _sign({}, "key"),
    "key",
    { jwtid: "foo" },
  ],
  [
    new JsonWebTokenError("jwt nonce invalid. expected: foo"),
    _sign({}, "key"),
    "key",
    { nonce: "foo" },
  ],
  [
    new JsonWebTokenError("maxAge exceeded"),
    _sign({ iat: now() - 10 }, "key"),
    "key",
    { maxAge: 5 },
  ],
])("%s", (error, token, key, options) => {
  expect(() => {
    verify(token, key, options);
  }).toThrow(error);
});

test("success", () => {
  expect(verify(_sign({}, "key"), "key")).toEqual({
    header: { typ: "JWT", alg: "HS256" },
    payload: { iat: expect.any(Number) },
    signature: expect.stringMatching(/^[\w\d-]+$/),
  });
});

function now() {
  return Math.floor(Date.now() / 1000);
}
