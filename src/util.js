import * as database from "./database";
import { decrypt, hashPassword } from "./crypto";
import { ClientError } from "./errors";

class AuthError extends ClientError {
  constructor(req, obj) {
    let headers = obj.headers || {};
    //if it was not an xhr request, tell the browser to prompt for a username/password
    if (!req.xhr) headers["WWW-Authenticate"] = 'Basic charset="UTF-8"';
    obj.headers = headers;
    super(obj);
  }
}

/**
 * A helper for creating routes. Automatically handles several things.
 * 1. Getting and releasing a DB connection
 * 2. Async handling
 * 3. Response body stringifying
 */
export function route(func) {
  return async (req, res, next) => {
    try {
      let conn = await database.getConnection();
      try {
        let body = await func(req, res, conn);
        if (body == null) body = {};
        let status = "status" in body ? body.status : 200;
        delete body.status;
        if (!("success" in body)) body.success = true;
        res.status(status).send(body);
      } finally {
        await database.releaseConnection(conn);
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Gets the authentication for this request. Throws an error if there is an authentcation problem.
 * If require is false, makes authentication optional.
 * If require is a string, enforces a specific type of authentication (credentials or token).
 * @return {{type: string, userId: string}}
 */
export async function authenticate(req, db, require = true) {
  let auth = req.get("authorization");
  if (auth != null) {
    if (
      auth.startsWith("Basic ") &&
      (typeof require !== "string" || require === "credentials")
    ) {
      let credentials = auth.slice(6);
      credentials = Buffer.from(credentials, "base64").toString("utf8");
      let i = credentials.indexOf(":");
      let username = credentials.slice(0, i);
      let password = credentials.slice(i + 1);
      let [results] = await db.query(
        `SELECT id as userId, password as hash, salt FROM todo.users WHERE username = ?`,
        [username]
      );
      if (results.length === 0) {
        throw new AuthError(req, {
          status: 401,
          code: "missing-user",
          message: "User not found.",
          data: username,
        });
      }
      let { userId, hash, salt } = results[0];
      let hash2 = await hashPassword(password, salt);
      if (Buffer.compare(hash, hash2) !== 0) {
        throw new AuthError(req, {
          status: 401,
          code: "invalid-password",
          message: "Invalid password.",
          data: username,
        });
      }
      return {
        type: "credentials",
        userId,
      };
    }
    if (
      auth.startsWith("Bearer ") &&
      (typeof require !== "string" || require === "token")
    ) {
      let token = auth.slice(7);
      let { sessionId } = await decrypt(token);
      let [results] = await db.query(
        `SELECT userId FROM todo.sessions WHERE id = ? AND expirationDate >= NOW()`,
        [sessionId]
      );
      if (results.length === 0) {
        throw new AuthError(req, {
          status: 401,
          code: "expired-session",
          message: "Session has expired",
        });
      }
      let { userId } = results[0];
      return {
        type: "token",
        userId,
        sessionId,
      };
    }
  }
  if (require) {
    throw new AuthError(req, {
      status: 401,
      code: "auth-required",
      message: "Authentication required",
    });
  }
  return { type: "none", userId: null };
}

function hasRole(role, required) {
  const roles = ["read", "write", "owner"];
  return roles.indexOf(role) >= roles.indexOf(required);
}

/**
 * Ensures that the given user has the permissions needed to enact a specific role on the given list. Throws an error if not allowed.
 */
export async function checkPermissions(req, db, userId, listId, role) {
  let [results] = await db.query(
    `SELECT role FROM todo.permissions WHERE IF(? IS NOT NULL, userId = ?, userId IS NULL) AND listId = ?`,
    [userId, userId, listId]
  );
  if (results.length === 0 || !hasRole(results[0].role, role)) {
    throw new AuthError(req, {
      status: 401,
      code: "insufficient-perms",
      message: "Insufficient permissions",
    });
  }
}
