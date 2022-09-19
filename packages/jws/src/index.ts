import { sign, Header } from "./lib/sign";
import { verify, decode, isValid } from "./lib/verify";

export const ALGORITHMS = [
  "HS256",
  "HS384",
  "HS512",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
];

export type { Header };
export { sign, verify, decode, isValid };
