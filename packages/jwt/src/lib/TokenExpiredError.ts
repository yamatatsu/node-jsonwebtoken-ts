import { JsonWebTokenError } from "./JsonWebTokenError"

export class TokenExpiredError extends JsonWebTokenError {
  public readonly name: string
  public readonly expiredAt: Date

  constructor(message: string, expiredAt: Date) {
    super(message)
    this.name = "TokenExpiredError"
    this.expiredAt = expiredAt
  }
}
