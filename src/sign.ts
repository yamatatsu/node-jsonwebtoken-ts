import jws from "jws"
import { timespan } from "./lib/timespan"

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
] as const

// TODO:
function isString(val: any): boolean {
  return true
}

// TODO:
function isInteger(val: any): boolean {
  return true
}

type Validator = { isValid: (value: any) => boolean; message: string }
type Schema = Record<string, Validator>

const sign_options_schema: Schema = {
  expiresIn: {
    isValid: (value) => isInteger(value) || (isString(value) && value),
    message:
      '"expiresIn" should be a number of seconds or string representing a timespan',
  },
  notBefore: {
    isValid: (value) => isInteger(value) || (isString(value) && value),
    message:
      '"notBefore" should be a number of seconds or string representing a timespan',
  },
  audience: {
    isValid: (value) => isString(value) || Array.isArray(value),
    message: '"audience" must be a string or array',
  },
  algorithm: {
    isValid: (value) => SUPPORTED_ALGS.includes(value),
    message: '"algorithm" must be a valid string enum value',
  },
}

function validate(
  schema: Schema,
  allowUnknown: boolean,
  object: Record<string, any>,
  parameterName: string,
) {
  Object.keys(object).forEach((key) => {
    const validator = schema[key]
    if (!validator) {
      if (!allowUnknown) {
        throw new Error(
          '"' + key + '" is not allowed in "' + parameterName + '"',
        )
      }
      return
    }
    if (!validator.isValid(object[key])) {
      throw new Error(validator.message)
    }
  })
}

function validateOptions(options: Record<string, any>) {
  return validate(sign_options_schema, false, options, "options")
}

const options_to_payload = {
  audience: "aud",
  issuer: "iss",
  subject: "sub",
  jwtid: "jti",
} as const

type Options = {
  algorithm?: typeof SUPPORTED_ALGS[number]
  keyid?: string
  header?: Record<string, any>
  encoding?: jws.SignOptions["encoding"]
  noTimestamp?: boolean
  mutatePayload?: boolean
  expiresIn?: number | string
  notBefore?: number | string

  audience?: string
  issuer?: string
  subject?: string
  jwtid?: string
}

type Payload = {
  exp?: number
  nbf?: number
  iat?: number
  sub?: string
  aud?: string
  iss?: string
  jti?: string
}

export function sign(
  payload: Payload,
  secretOrPrivateKey: any,
  options: Options = {},
) {
  const header = Object.assign(
    {
      alg: options.algorithm || "HS256",
      typ: "JWT",
      kid: options.keyid,
    },
    options.header,
  )

  if (!secretOrPrivateKey && options.algorithm !== "none") {
    throw new Error("secretOrPrivateKey must have a value")
  }

  payload = Object.assign({}, payload)

  if (payload.exp !== undefined && options.expiresIn !== undefined) {
    throw new Error(
      'Bad "options.expiresIn" option the payload already has an "exp" property.',
    )
  }

  if (payload.nbf !== undefined && options.notBefore !== undefined) {
    throw new Error(
      'Bad "options.notBefore" option the payload already has an "nbf" property.',
    )
  }

  try {
    validateOptions(options)
  } catch (error) {
    throw error
  }

  const timestamp = payload.iat || Math.floor(Date.now() / 1000)

  if (options.noTimestamp) {
    delete payload.iat
  } else {
    payload.iat = timestamp
  }

  if (options.notBefore !== undefined) {
    payload.nbf = timespan(options.notBefore, timestamp)

    if (payload.nbf === undefined) {
      throw new Error(
        '"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60',
      )
    }
  }

  if (options.expiresIn !== undefined && typeof payload === "object") {
    payload.exp = timespan(options.expiresIn, timestamp)

    if (payload.exp === undefined) {
      throw new Error(
        '"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60',
      )
    }
  }

  Object.entries(options_to_payload).forEach(([key, claim]) => {
    if (options[key as keyof typeof options_to_payload] !== undefined) {
      if (payload[claim] !== undefined) {
        throw new Error(
          'Bad "options.' +
            key +
            '" option. The payload already has an "' +
            claim +
            '" property.',
        )
      }
      payload[claim] = options[key as keyof typeof options_to_payload]
    }
  })

  const encoding = options.encoding || "utf8"

  return jws.sign({
    header: header,
    payload: payload,
    secret: secretOrPrivateKey,
    encoding: encoding,
  })
}
