import jwa, { Algorithm } from "@node-jsonwebtoken-ts/jwa";

function base64url(obj: object | string | Buffer) {
  const stringLike = typeof obj === "object" ? JSON.stringify(obj) : obj;
  return Buffer.from(stringLike).toString("base64url");
}

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
