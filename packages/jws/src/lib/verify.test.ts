import { describe, test, expect } from "vitest";
import { sign as _sign, decode as _decode } from "jws";
import { verify, decode } from "./verify";

describe("verify()", () => {
  test.each([
    [
      "valid token",
      _sign({ header: { alg: "HS256" }, payload: {}, secret: "key" }),
      "HS256",
      "key",
    ] as const,
  ])("%s", (_, token, algorithm, key) => {
    expect(verify(token, algorithm, key)).toEqual(
      verify(token, algorithm, key)
    );
  });
});

describe("decode()", () => {
  test.each([
    ["invalid token", "a.b.c"],
    [
      "valid token",
      _sign({ header: { alg: "HS256" }, payload: {}, secret: "key" }),
    ],
  ])("", (_, token) => {
    expect(decode(token)).toEqual(_decode(token));
  });
});
