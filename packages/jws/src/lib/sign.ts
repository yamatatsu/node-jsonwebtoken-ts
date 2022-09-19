import jwa, { Algorithm } from "@node-jsonwebtoken-ts/jwa";

function base64url(obj: object | string | Buffer) {
  const stringLike = typeof obj === "object" ? JSON.stringify(obj) : obj;
  return Buffer.from(stringLike).toString("base64url");
}

export type Header = CertificateProperties & {
  alg: Algorithm;
  jwk?: JWK | undefined;
  typ?: string | undefined;
  cty?: string | undefined;
  crit?: ReadonlyArray<string> | undefined;
};

export type JWK = CertificateProperties & {
  alg?: Algorithm | undefined;
  kty: string;
  use?: string | undefined;
  key_ops?: ReadonlyArray<string> | undefined;
};

export type CertificateProperties = PrivateProperties & {
  kid?: string | undefined;
  x5u?: string | undefined;
  x5c?: ReadonlyArray<string> | undefined;
  x5t?: string | undefined;
  "x5t#S256"?: string | undefined;
};

export type PrivateProperties = {
  [name: string]: any;
};

type Options = {
  header: { alg: Algorithm };
  payload: object | string | Buffer;
  secretOrKey: string;
};

export function sign(opts: Options) {
  const { header, payload, secretOrKey } = opts;

  const algo = jwa(header.alg);
  const securedInput = `${base64url(header)}.${base64url(payload)}`;
  const signature = algo.sign(securedInput, secretOrKey);
  return `${securedInput}.${signature}`;
}
