/**
 * @fileoverview SuperTest extensions providing custom assertion methods for
 * common HTTP testing patterns including redirects and cookie validation.
 *
 * This module patches SuperTest's prototype to add chainable methods that
 * simplify testing of redirects and Set-Cookie headers. The extensions work
 * with both supertest.Test and superagent.Request interfaces.
 */

// noinspection JSUnusedGlobalSymbols

import { agent as SuperAgent } from 'superagent';
import { URL } from 'url';
import { CookieAccessInfo } from 'cookiejar';
import request, { Response, Test as STTest } from 'supertest';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const originalAttachCookies = (SuperAgent.prototype as any)._attachCookies;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(SuperAgent.prototype as any)._attachCookies = function (request_: any) {
  if (process.env.TEST_SECURE_COOKIES === 'true') {
    const url = new URL(request_.url);
    const access = new CookieAccessInfo(url.hostname, url.pathname, true);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (request_ as any).cookies = this.jar.getCookies(access).toValueString();
  } else {
    Reflect.apply(originalAttachCookies, this, [request_]);
  }
};

/**
 * Module augmentations so TypeScript knows about the chainers on either
 * supertest.Test or superagent.Request shapes.
 */
declare module 'supertest' {
  // noinspection JSUnusedGlobalSymbols
  interface Test {
    /**
     * Asserts that the response is a 302 redirect to the specified path.
     * @param path - The expected redirect path (including query parameters)
     */
    expectRedirectTo(path: string): this;

    /**
     * Asserts that a Set-Cookie header with the given name is present.
     * @param name - The cookie name to look for
     * @param options - Additional cookie validation options
     */
    expectCookie(name: string, options?: { secure?: boolean }): this;
  }
}
declare module 'superagent' {
  // noinspection JSUnusedGlobalSymbols
  interface Request {
    /**
     * Asserts that the response is a 302 redirect to the specified path.
     * @param path - The expected redirect path (including query parameters)
     */
    expectRedirectTo(path: string): this;

    /**
     * Asserts that a Set-Cookie header with the given name is present.
     * @param name - The cookie name to look for
     * @param options - Additional cookie validation options
     */
    expectCookie(name: string, options?: { secure?: boolean }): this;
  }
}

/** Options for cookie assertion validation. */
type CookieOpts = { secure?: boolean };

/**
 * Asserts that the HTTP response is a 302 redirect to the expected path.
 *
 * Validates both the status code and Location header, comparing the full
 * path including query parameters against the expected value.
 *
 * @param res - The HTTP response to validate
 * @param path - The expected redirect path (pathname + search)
 * @throws Error if not a 302 redirect or path doesn't match
 */
function assertRedirectTo(res: Response, path: string): void {
  if (res.status !== 302) {
    throw new Error(`expected 302 redirect, got ${res.status}`);
  }
  const headers = (res.headers ?? {}) as Record<
    string,
    string | string[] | undefined
  >;
  const loc = headers.location as string | undefined;
  if (!loc) {
    throw new Error('missing Location header on redirect');
  }
  const url = new URL(loc, 'http://127.0.0.1');
  const got = url.pathname + url.search;
  if (got !== path) {
    throw new Error(`expected redirect to "${path}", got "${got}"`);
  }
}

/**
 * Asserts that a Set-Cookie header with the specified name is present and
 * optionally validates cookie attributes like the Secure flag.
 *
 * Searches through all Set-Cookie headers to find one that starts with the
 * given cookie name. If options.secure is specified, also validates whether
 * the Secure attribute is present on the cookie.
 *
 * @param res - The HTTP response to validate
 * @param name - The cookie name to search for
 * @param opts - Optional validation criteria for cookie attributes
 * @throws Error if cookie not found or attributes don't match expectations
 */
function assertCookie(
  res: Response,
  name: string,
  opts: CookieOpts = {},
): void {
  const headers = (res.headers ?? {}) as Record<
    string,
    string | string[] | undefined
  >;
  const raw = headers['set-cookie'];
  const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
  if (list.length === 0) {
    throw new Error('expected Set-Cookie header');
  }
  const cookie = list.find(
    (c) => typeof c === 'string' && c.startsWith(`${name}=`),
  );
  if (!cookie) {
    throw new Error(`expected cookie "${name}"`);
  }
  if (opts.secure !== undefined) {
    const hasSecure = /;\s*secure\b/i.test(cookie);
    if (hasSecure !== opts.secure) {
      throw new Error(
        `expected cookie "${name}" Secure=${String(opts.secure)}, got ${String(hasSecure)}`,
      );
    }
  }
}

/**
 * Runtime prototype patch – attach chainers to SuperTest's Test prototype.
 *
 * This section dynamically adds the custom assertion methods to SuperTest's
 * Test class prototype, enabling method chaining with existing SuperTest
 * assertions. The patch is applied only once per module load and only if
 * the methods don't already exist.
 */
interface TestProto {
  expect(handler: (res: Response) => void): STTest;
  expectRedirectTo?(path: string): STTest;
  expectCookie?(name: string, options?: CookieOpts): STTest;
}

/** Constructor type with prototype property for runtime patching. */
type MaybeTestConstructor = { prototype: TestProto };

/** SuperTest module type extended with optional Test constructor. */
type SupertestModuleWithCtor = typeof import('supertest') & {
  Test?: MaybeTestConstructor;
};

const STCtor: MaybeTestConstructor | undefined = (
  request as SupertestModuleWithCtor
).Test;

// Patch expectRedirectTo method if not already present
if (STCtor && !('expectRedirectTo' in STCtor.prototype)) {
  STCtor.prototype.expectRedirectTo = function (
    this: STTest,
    path: string,
  ): STTest {
    return this.expect((res: Response) => assertRedirectTo(res, path));
  };
}

// Patch expectCookie method if not already present
if (STCtor && !('expectCookie' in STCtor.prototype)) {
  STCtor.prototype.expectCookie = function (
    this: STTest,
    name: string,
    options?: CookieOpts,
  ): STTest {
    return this.expect((res: Response) => assertCookie(res, name, options));
  };
}

/**
 * Optional superagent.Request prototype patching.
 *
 * Some SuperTest chains might be typed as superagent.Request since Test
 * extends superagent.Request. The type declarations above cover this case,
 * and if runtime patching is ever needed for superagent.Request, the
 * commented code below provides a safe implementation pattern.
 *
 * @example
 * ```ts
 * import type superagent from 'superagent';
 * type SuperagentWithCtor = typeof import('superagent') & {
 *   Request?: { prototype: TestProto }
 * };
 * const SAReq = (superagent as unknown as SuperagentWithCtor).Request;
 * if (SAReq && !('expectCookie' in SAReq.prototype)) {
 *   // Apply patches here
 * }
 * ```
 */

export {};
