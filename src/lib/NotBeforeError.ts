import { JsonWebTokenError } from "./JsonWebTokenError"

export class NotBeforeError extends JsonWebTokenError {
  public readonly name: string
  public readonly date: Date

  constructor(message: string, date: Date) {
    super(message)
    this.name = "NotBeforeError"
    this.date = date
  }
}
