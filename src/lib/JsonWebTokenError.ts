export class JsonWebTokenError extends Error {
  public readonly name: string
  public readonly message: string
  public readonly inner?: Error

  constructor(message: string, error?: Error) {
    super(message)

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor)
    }

    this.name = "JsonWebTokenError"
    this.message = message
    if (error) this.inner = error
  }
}
