/**
 * Keep internal execution-backend names out of the operations UI. Historical
 * rows may contain the old wording even after the gateway is upgraded, so this
 * is intentionally applied at display time as well as at write time.
 */
export function sanitizeOpsErrorMessage(raw: unknown): string {
  return String(raw ?? '')
    .replace(/\bpi_request_error\b/gi, 'invalid_request_error')
    .replace(/\bpi\b/gi, 'selected execution backend')
}
