/** Return true for both a native Pi owner account and a shared Pi alias. */
export function isPiHarnessKind(value: unknown): boolean {
  return value === 'pi' || value === 'pi_shared'
}
