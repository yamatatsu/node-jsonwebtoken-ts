import { test, expect } from "vitest";
import { sign as _sign } from "jws";
import { sign } from "./sign";

test("success", () => {
  const arg = {
    header: { alg: "HS256" },
    payload: {},
    secretOrKey: "key",
    secret: "key",
  } as const;
  expect(sign(arg)).toBe(_sign(arg));
});
