import { decode, decodeCompletely } from "./decode"
import { verify } from "./verify"
import { sign } from "./sign"
import { JsonWebTokenError } from "./lib/JsonWebTokenError"
import { NotBeforeError } from "./lib/NotBeforeError"
import { TokenExpiredError } from "./lib/TokenExpiredError"

export default {
  decode,
  decodeCompletely,
  verify,
  sign,
  JsonWebTokenError,
  NotBeforeError,
  TokenExpiredError,
}

export {
  decode,
  decodeCompletely,
  verify,
  sign,
  JsonWebTokenError,
  NotBeforeError,
  TokenExpiredError,
}
