import jws from "jws"

type DecodeCompletelyResult = {
  header: jws.Header
  payload: any
  signature: string
}
export function decode(jwt: string): DecodeCompletelyResult | null {
  const decoded = jws.decode(jwt)
  if (!decoded) {
    return null
  }

  const payload = parsePayload(decoded.payload)

  return {
    header: decoded.header,
    payload: payload,
    signature: decoded.signature,
  }
}

function parsePayload(raw: any) {
  if (typeof raw !== "string") return raw

  try {
    const obj = JSON.parse(raw)
    if (obj !== null && typeof obj === "object") {
      return obj
    }
    return raw
  } catch (e) {}
}
