import { test, expect } from "vitest";
import { sign as _sign, decode as _decode } from "jsonwebtoken";
import { decode } from "./decode";

test("empty", () => {
  expect(decode("")).toBeNull();
});

test("not empty", () => {
  const token = _sign({}, "key");
  expect(decode(token)).toEqual(_decode(token, { complete: true }));
});
