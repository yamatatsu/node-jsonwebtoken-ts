import { test, expect } from "vitest";
import { sign as _sign } from "jws";
import { sign } from "./sign";

test.each([
  {
    header: { alg: "HS256" },
    payload: {},
    secretOrKey: "key",
    secret: "key",
  } as const,
  {
    header: { alg: "HS256" },
    payload: "",
    secretOrKey: "key",
    secret: "key",
  } as const,
])("success", (arg) => {
  expect(sign(arg)).toBe(_sign(arg));
});
