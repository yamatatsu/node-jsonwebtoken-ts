import jws from "jws";

const SUPPORTED_ALGS = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "HS256",
  "HS384",
  "HS512",
  "none",
] as const;

type SupportedAlgs = typeof SUPPORTED_ALGS[number];

const options_to_payload = [
  ["audience", "aud"],
  ["issuer", "iss"],
  ["subject", "sub"],
  ["jwtid", "jti"],
] as const;

export type Payload = {
  exp?: number;
  nbf?: number;
  iat?: number;
  sub?: string;
  aud?: string;
  iss?: string;
  jti?: string;
};

export type Secret =
  | string
  | Buffer
  | { key: string | Buffer; passphrase: string };

export type Options = {
  algorithm?: SupportedAlgs;
  keyid?: string;
  header?: Record<string, any>;
  encoding?: jws.SignOptions["encoding"];
  noTimestamp?: boolean;
  mutatePayload?: boolean;
  expiresIn?: number;
  notBefore?: number;

  audience?: string;
  issuer?: string;
  subject?: string;
  jwtid?: string;
};

export function sign(
  _payload: Payload,
  secretOrPrivateKey: Secret,
  options: Options = {}
) {
  const payload = { ..._payload };

  if (!secretOrPrivateKey && options.algorithm !== "none") {
    throw new Error("secretOrPrivateKey must have a value");
  }

  if (payload.exp !== undefined && options.expiresIn !== undefined) {
    throw new Error(
      'Bad "options.expiresIn" option the payload already has an "exp" property.'
    );
  }

  if (payload.nbf !== undefined && options.notBefore !== undefined) {
    throw new Error(
      'Bad "options.notBefore" option the payload already has an "nbf" property.'
    );
  }

  if (
    options.algorithm !== undefined &&
    !SUPPORTED_ALGS.includes(options.algorithm)
  ) {
    throw new Error('"algorithm" must be a valid string enum value');
  }

  const timestamp = payload.iat || Math.floor(Date.now() / 1000);

  if (options.noTimestamp) {
    delete payload.iat;
  } else {
    payload.iat = timestamp;
  }

  if (options.notBefore !== undefined) {
    payload.nbf = options.notBefore + timestamp;
  }

  if (options.expiresIn !== undefined) {
    payload.exp = options.expiresIn + timestamp;
  }

  options_to_payload.forEach(([key, claim]) => {
    if (options[key] !== undefined) {
      if (payload[claim] !== undefined) {
        throw new Error(
          'Bad "options.' +
            key +
            '" option. The payload already has an "' +
            claim +
            '" property.'
        );
      }
      payload[claim] = options[key];
    }
  });

  const encoding = options.encoding || "utf8";

  return jws.sign({
    header: {
      alg: options.algorithm || "HS256",
      typ: "JWT",
      kid: options.keyid,
      ...options.header,
    },
    payload: payload,
    secret: secretOrPrivateKey,
    encoding: encoding,
  });
}
