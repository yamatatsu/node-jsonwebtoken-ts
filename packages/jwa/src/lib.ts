import util from "util";

const MSG_INVALID_ALGORITHM =
  '"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".';

export function getAlgAndBits(
  algorithm: string
): ["rs" | "ps" | "es" | "hs" | "none", string] {
  if (algorithm === "none") {
    return ["none", ""];
  }

  const match = algorithm.match(/^(RS|PS|ES|HS)(256|384|512)$|^(none)$/);
  if (!match) throw typeError(MSG_INVALID_ALGORITHM, algorithm);
  const algo = (match[1] || match[3]).toLowerCase() as
    | "rs"
    | "ps"
    | "es"
    | "hs"
    | "none";
  const bits = match[2];
  return [algo, bits];
}

export function typeError(template: string, ...args: any[]) {
  const errMsg = util.format(template, args);
  return new TypeError(errMsg);
}
