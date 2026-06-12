/**
 * Minimal subset-JSON-Schema validator for the cross-language state contract
 * (PLAN.md D4): the TS mirror of adw/test_state.py _validate, covering
 * exactly the keywords adw/state.schema.json uses
 * (type/required/properties/items/pattern/minimum). Shared by the state
 * contract suite and the engine-parity suite — not a test file itself.
 */

export type Schema = Record<string, unknown>;

function isType(value: unknown, jsonType: string): boolean {
  switch (jsonType) {
    case 'string':
      return typeof value === 'string';
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value);
    case 'number':
      return typeof value === 'number';
    case 'boolean':
      return typeof value === 'boolean';
    case 'null':
      return value === null;
    case 'array':
      return Array.isArray(value);
    case 'object':
      return typeof value === 'object' && value !== null && !Array.isArray(value);
    default:
      return false;
  }
}

/** Validate `instance` against the schema subset; returns [] when valid. */
export function validate(instance: unknown, schema: Schema, path = '$'): string[] {
  const errors: string[] = [];
  const declared = schema['type'];
  if (declared !== undefined) {
    const types = Array.isArray(declared) ? declared : [declared];
    if (!types.some((t) => isType(instance, String(t)))) {
      return [`${path}: ${JSON.stringify(instance)} is not of type ${JSON.stringify(types)}`];
    }
  }
  if (typeof instance === 'object' && instance !== null && !Array.isArray(instance)) {
    const doc = instance as Record<string, unknown>;
    for (const required of (schema['required'] as string[] | undefined) ?? []) {
      if (!(required in doc)) {
        errors.push(`${path}: missing required key ${JSON.stringify(required)}`);
      }
    }
    const properties = (schema['properties'] as Record<string, Schema> | undefined) ?? {};
    for (const [key, subschema] of Object.entries(properties)) {
      if (key in doc) {
        errors.push(...validate(doc[key], subschema, `${path}.${key}`));
      }
    }
  }
  if (Array.isArray(instance)) {
    const items = schema['items'];
    if (typeof items === 'object' && items !== null) {
      instance.forEach((element, i) => {
        errors.push(...validate(element, items as Schema, `${path}[${i}]`));
      });
    }
  }
  if (typeof instance === 'string') {
    const pattern = schema['pattern'];
    if (typeof pattern === 'string' && !new RegExp(pattern).test(instance)) {
      errors.push(`${path}: ${JSON.stringify(instance)} does not match pattern ${JSON.stringify(pattern)}`);
    }
  }
  if (typeof instance === 'number' && Number.isInteger(instance)) {
    const minimum = schema['minimum'];
    if (typeof minimum === 'number' && instance < minimum) {
      errors.push(`${path}: ${instance} is below minimum ${minimum}`);
    }
  }
  return errors;
}
