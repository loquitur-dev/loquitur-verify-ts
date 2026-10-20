/**
 * Put a JSON member on an object by definition, never by assignment.
 *
 * `out[k] = v` with k === "__proto__" does not create a member: it calls the setter
 * Object.prototype carries under that name and changes the object's prototype instead, so the
 * member would be missing from every digest, signature and comparison taken over `out`. RFC 8259
 * and RFC 8785 treat that member name like any other. Not exported from the package.
 */
export function defineJsonMember(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}
