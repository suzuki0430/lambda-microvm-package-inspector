/**
 * Return a deterministic greeting used by the benign package fixture.
 *
 * @param {string} name - Name to include in the greeting.
 * @returns {string} A deterministic greeting without side effects.
 * @example
 * greeting('MicroVM'); // "Hello, MicroVM."
 */
export function greeting(name) {
  return `Hello, ${name}.`;
}
