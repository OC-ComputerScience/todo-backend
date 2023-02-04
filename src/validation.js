import { ClientError } from "./errors";

/**
 * Wraps a value to make an entry optional
 */
export class Optional {
  constructor(value) {
    this.value = value;
  }

  toJSON() {
    return this.value;
  }
}

/**
 * Returns the json type of a value
 */
export function jsonType(value) {
  if (value == null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "object") return "object";
  if (typeof value === "string") return "string";
  if (typeof value === "number") return "number";
  if (typeof value === "boolean") return "boolean";
  return "unknown";
}

/**
 * Joins the given strings with a dot, filtering out null and empty strings.
 */
function join(...parts) {
  return parts.filter(Boolean).join(".");
}

/**
 * Subtracts everything in arr2 from arr.
 */
function minus(arr, arr2) {
  let set = new Set(arr2);
  return arr.filter((ele) => !set.has(ele));
}

/**
 * Validates that the given body matches the expected form. See server.js for examples of usage.
 */
export function jsonValidate(actual, expected, path = null) {
  if (expected instanceof Optional) {
    if (actual == null || actual === "") return actual;
    expected = expected.value;
  }
  let actualType = jsonType(actual);
  let expectedType = jsonType(expected);
  if (expectedType !== actualType) {
    if (path == null && actual === undefined) {
      throw new ClientError({
        code: "invalid-body",
        message: `Invalid body. Please set the 'Content-Type' header to 'application/json'.`,
      });
    } else {
      throw new ClientError({
        code: "invalid-body",
        message: `Invalid ${
          path || "body"
        }. Expected '${expectedType}' but got '${actualType}'. See data for an example of the correct format.`,
        data: expected,
      });
    }
  }
  switch (expectedType) {
    case "string": {
      if (actual.length === 0) {
        throw new ClientError({
          code: "missing-fields",
          message: `Invalid ${path || "body"}. Cannot be empty.`,
          data: actual,
        });
      }
      break;
    }
    case "array": {
      for (let i = 0; i < actual.length; i++)
        jsonValidate(actual[i], expected[i % expected.length], join(path, i));
      break;
    }
    case "object": {
      let actualKeys = Object.keys(actual);
      let expectedKeys = Object.keys(expected);
      let missingKeys = minus(
        expectedKeys.filter((key) => !(expected[key] instanceof Optional)),
        actualKeys
      );
      if (missingKeys.length > 0) {
        throw new ClientError({
          code: "missing-fields",
          message: `Missing required fields in ${
            path || "body"
          }. These must be provided. See data for missing fields.`,
          data: missingKeys,
        });
      }
      let unexpectedKeys = minus(actualKeys, expectedKeys);
      if (unexpectedKeys.length > 0) {
        throw new ClientError({
          code: "unexpected-fields",
          message: `Unexpected fields in ${
            path || "body"
          }. Remove these. See data for unexpected fields.`,
          data: unexpectedKeys,
        });
      }
      for (let key of expectedKeys) {
        let actualValue = actual[key];
        let expectedValue = expected[key];
        jsonValidate(actualValue, expectedValue, join(path, key));
      }
      break;
    }
  }
  return actual;
}

/**
 * Parses an integer, returning NaN if it is not a valid number.
 */
export function parseIntStrict(x) {
  if (/^([-+])?(\d+|Infinity)$/.test(x)) return Number(x);
  return NaN;
}
