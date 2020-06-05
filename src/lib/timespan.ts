import ms from "ms"

export function timespan(time: string | number, iat: number) {
  const timestamp = iat || Math.floor(Date.now() / 1000)

  if (typeof time === "number") {
    return timestamp + time
  }

  const milliseconds = ms(time)
  if (typeof milliseconds === "undefined") {
    return
  }

  return Math.floor(timestamp + milliseconds / 1000)
}
