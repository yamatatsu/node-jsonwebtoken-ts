import jws from "jws";
import { decode } from "./decode";
import { JsonWebTokenError } from "./lib/JsonWebTokenError";
import { NotBeforeError } from "./lib/NotBeforeError";
import { TokenExpiredError } from "./lib/TokenExpiredError";

const PUB_KEY_ALGS = [
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
const RSA_KEY_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"];
const HS_ALGS = ["HS256", "HS384", "HS512"];

type Options = {
  clockTimestamp?: number;
  nonce?: string;
  algorithms?: string[];
  ignoreNotBefore?: string;
  clockTolerance?: number;
  ignoreExpiration?: string;
  audience?: (string | RegExp)[];
  issuer?: string;
  subject?: string;
  jwtid?: string;
  maxAge?: number;
  complete?: string;
};

export function verify(
  jwtString: string,
  secretOrPublicKey: any,
  _options: Options = {}
) {
  //clone this object since we are going to mutate it.
  const options = { ..._options };

  if (options.nonce?.trim() === "") {
    throw new JsonWebTokenError("nonce must be a non-empty string");
  }

  const clockTimestamp =
    options.clockTimestamp || Math.floor(Date.now() / 1000);

  const parts = jwtString.split(".");

  if (parts.length !== 3) {
    throw new JsonWebTokenError("jwt malformed");
  }

  const decodedToken = decode(jwtString);

  if (!decodedToken) {
    throw new JsonWebTokenError("invalid token");
  }

  const header = decodedToken.header;

  const hasSignature = parts[2].trim() !== "";

  if (!hasSignature && secretOrPublicKey) {
    throw new JsonWebTokenError("jwt signature is required");
  }

  if (hasSignature && !secretOrPublicKey) {
    throw new JsonWebTokenError("secret or public key must be provided");
  }

  if (!hasSignature && !options.algorithms) {
    options.algorithms = ["none"];
  }

  if (!options.algorithms) {
    options.algorithms =
      secretOrPublicKey.toString().includes("BEGIN CERTIFICATE") ||
      secretOrPublicKey.toString().includes("BEGIN PUBLIC KEY")
        ? PUB_KEY_ALGS
        : secretOrPublicKey.toString().includes("BEGIN RSA PUBLIC KEY")
        ? RSA_KEY_ALGS
        : HS_ALGS;
  }

  if (!~options.algorithms.indexOf(decodedToken.header.alg)) {
    throw new JsonWebTokenError("invalid algorithm");
  }

  const valid = jws.verify(
    jwtString,
    decodedToken.header.alg,
    secretOrPublicKey
  );

  if (!valid) {
    throw new JsonWebTokenError("invalid signature");
  }

  const payload = decodedToken.payload;

  if (payload.nbf !== undefined && !options.ignoreNotBefore) {
    if (typeof payload.nbf !== "number") {
      throw new JsonWebTokenError("invalid nbf value");
    }
    if (payload.nbf > clockTimestamp + (options.clockTolerance || 0)) {
      throw new NotBeforeError("jwt not active", new Date(payload.nbf * 1000));
    }
  }

  if (payload.exp !== undefined && !options.ignoreExpiration) {
    if (typeof payload.exp !== "number") {
      throw new JsonWebTokenError("invalid exp value");
    }
    if (clockTimestamp >= payload.exp + (options.clockTolerance || 0)) {
      throw new TokenExpiredError("jwt expired", new Date(payload.exp * 1000));
    }
  }

  if (options.audience) {
    const audiences = options.audience;
    const target: any[] = Array.isArray(payload.aud)
      ? payload.aud
      : [payload.aud];

    const match = target.some((targetAudience) => {
      return audiences.some((audience) => {
        return audience instanceof RegExp
          ? audience.test(targetAudience)
          : audience === targetAudience;
      });
    });

    if (!match) {
      throw new JsonWebTokenError(
        "jwt audience invalid. expected: " + audiences.join(" or ")
      );
    }
  }

  if (options.issuer) {
    const invalid_issuer =
      (typeof options.issuer === "string" && payload.iss !== options.issuer) ||
      (Array.isArray(options.issuer) &&
        options.issuer.indexOf(payload.iss) === -1);

    if (invalid_issuer) {
      throw new JsonWebTokenError(
        "jwt issuer invalid. expected: " + options.issuer
      );
    }
  }

  if (options.subject) {
    if (payload.sub !== options.subject) {
      throw new JsonWebTokenError(
        "jwt subject invalid. expected: " + options.subject
      );
    }
  }

  if (options.jwtid) {
    if (payload.jti !== options.jwtid) {
      throw new JsonWebTokenError(
        "jwt jwtid invalid. expected: " + options.jwtid
      );
    }
  }

  if (options.nonce) {
    if (payload.nonce !== options.nonce) {
      throw new JsonWebTokenError(
        "jwt nonce invalid. expected: " + options.nonce
      );
    }
  }

  if (options.maxAge) {
    if (typeof payload.iat !== "number") {
      throw new JsonWebTokenError("iat required when maxAge is specified");
    }

    const maxAgeTimestamp = options.maxAge + payload.iat;
    if (maxAgeTimestamp === undefined) {
      throw new JsonWebTokenError(
        '"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'
      );
    }
    if (clockTimestamp >= maxAgeTimestamp + (options.clockTolerance || 0)) {
      throw new TokenExpiredError(
        "maxAge exceeded",
        new Date(maxAgeTimestamp * 1000)
      );
    }
  }

  const signature = decodedToken.signature;

  return {
    header: header,
    payload: payload,
    signature: signature,
  };
}
