/**
 * :::warning
 * `@auth/fastify` is currently experimental. The API _will_ change in the
 * future.
 * :::
 *
 * Fastify Auth is the official Fastify integration for Auth.js.
 * It provides a simple way to add authentication to your Fastify app in a
 * few lines of code.
 *
 * ## Installation
 * ```bash npm2yarn
 * npm install @auth/fastify
 * ```
 *
 * ## Usage
 *
 * ```ts title="src/routes/auth.route.ts"
 * import { FastifyAuth } from "@auth/fastify"
 * import GitHub from "@auth/fastify/providers/github"
 * import Fastify from "fastify"
 *
 * // If app is served through a proxy, trust the proxy to allow HTTPS
 * // protocol to be detected
 * const fastify = Fastify({ trustProxy: true });
 *
 * fastify.register(FastifyAuth({ providers: [ GitHub ] }),
 *   { prefix: '/auth' })
 * ```
 *
 * Don't forget to set the `AUTH_SECRET` environment variable. This should be
 * a minimum of 32 characters, random string. On UNIX systems you can use
 * `openssl rand -hex 32` or check out `https://generate-secret.vercel.app/32`.
 *
 * ### Provider Configuration
 * The callback URL used by the
 * [providers](https://authjs.dev/reference/core/modules/providers) must be
 * set to the following, unless you mount the `FastifyAuth` handler on a
 * different path:
 *
 * ```
 * [origin]/auth/callback/[provider]
 * ```
 *
 * ## Managing the session
 * If you are using Fastify with a template engine (e.g., @fastify/view with
 * EJS, Pug), you can make the session data available to all routes via a
 * preHandler hook as follows
 *
 * ```ts title="app.ts"
 * import { getSession } from "@auth/fastify"
 *
 * // Decorating the reply is not required but will optimise performance
 * // Only decorate the reply with a value type like null, as reference types
 * // like objects are shared among all requests, creating a security risk.
 * fastify.decorateReply('session', null)
 *
 * export async function authSession(req: FastifyRequest,
 *   reply: FastifyReply) {
 *   reply.session = await getSession(req, authConfig)
 * }
 *
 * fastify.addHook("preHandler", authSession)
 *
 * // Now in your route
 * fastify.get("/", (req, reply) => {
 *   const session = reply.session;
 *   reply.view("index.pug", { user: session?.user })
 * })
 * ```
 *
 * Note for TypeScript, you may want to augment the Fastify types to include
 * the `session` property on the reply object:
 *
 * ```ts title="@types/fastify/index.d.ts"
 * import { Session } from "@auth/fastify";
 * declare module "fastify" {
 *   interface FastifyReply {
 *     session: Session | null;
 *   }
 * }
 * ```
 *
 * ## Authorization
 * You can protect routes with hooks by checking for the presence of a session
 * and then redirect to a login page if the session is not present.
 *
 * ```ts
 * export async function authenticatedUser(
 *   req: FastifyRequest,
 *   reply: FastifyReply
 * ) {
 *   reply.session ??= await getSession(req, authConfig);
 *   if (!reply.session?.user) {
 *     reply.redirect("/auth/signin?error=SessionRequired");
 *   }
 * }
 * ```
 *
 * @module @auth/fastify
 */

import {
  Auth,
  type AuthConfig,
  setEnvDefaults,
  createActionURL,
} from '@auth/core';
import type { Session } from '@auth/core/types';
import type {
  FastifyRequest,
  FastifyPluginAsync,
  FastifyInstance,
} from 'fastify';
import formbody from '@fastify/formbody';
import { toWebRequest, toFastifyReply } from './lib/index.js';

/**
 * Configuration options for Fastify Auth, extending Auth.js core config
 * but excluding the raw property which is not applicable to Fastify.
 */
export type FastifyAuthConfig = Omit<AuthConfig, 'raw'>;

/**
 * Promise that resolves to a session or null if no session exists.
 */
export type GetSessionResult = Promise<Session | null>;

export type {
  Account,
  DefaultSession,
  Profile,
  Session,
  User,
} from '@auth/core/types';

/**
 * Augment the Fastify module to include session on the reply object
 */
declare module 'fastify' {
  interface FastifyReply {
    session: Session | null;
  }
}

/**
 * Creates a Fastify plugin that handles authentication routes and sessions.
 *
 * This plugin registers all necessary Auth.js routes (signin, signout,
 * callback, etc.) and handles the authentication flow for your Fastify
 * application.
 *
 * @param config - The authentication configuration object
 * @returns A Fastify plugin async function
 *
 * @example
 * ```ts
 * import { FastifyAuth } from "@auth/fastify"
 * import GitHub from "@auth/fastify/providers/github"
 *
 * const authPlugin = FastifyAuth({
 *   providers: [GitHub],
 *   secret: process.env.AUTH_SECRET
 * })
 *
 * fastify.register(authPlugin, { prefix: "/auth" })
 * ```
 */
export function FastifyAuth(config: FastifyAuthConfig): FastifyPluginAsync {
  setEnvDefaults(process.env, config);

  return async (fastify: FastifyInstance) => {
    // Register form body parser if not already registered
    if (!fastify.hasContentTypeParser('application/x-www-form-urlencoded')) {
      await fastify.register(formbody);
    }

    // Register the catch-all route for Auth.js
    fastify.route({
      method: ['GET', 'POST'],
      url: '/*',
      handler: async (request, reply) => {
        config.basePath = getBasePath(request);
        const response = await Auth(toWebRequest(request), config);
        return toFastifyReply(response, reply);
      },
    });
  };
}

/**
 * Retrieves the current session for a Fastify request.
 *
 * This function extracts session information from the request cookies and
 * validates it against the Auth.js configuration. It returns the session
 * object if valid, or null if no valid session exists.
 *
 * @param req - The Fastify request object
 * @param config - The authentication configuration
 * @returns Promise resolving to session data or null
 *
 * @throws {Error} When session validation fails or Auth.js returns an error
 *
 * @example
 * ```ts
 * fastify.get("/profile", async (request, reply) => {
 *   const session = await getSession(request, authConfig)
 *
 *   if (!session) {
 *     reply.status(401).send({ error: "Not authenticated" })
 *     return
 *   }
 *
 *   reply.send({ user: session.user })
 * })
 * ```
 */
export async function getSession(
  req: FastifyRequest,
  config: FastifyAuthConfig,
): GetSessionResult {
  setEnvDefaults(process.env, config);

  const url = createActionURL(
    'session',
    req.protocol,
    // @ts-expect-error - Fastify headers are compatible with Headers constructor
    new Headers(req.headers),
    process.env,
    config,
  );

  const response = await Auth(
    new Request(url, { headers: { cookie: req.headers.cookie ?? '' } }),
    config,
  );

  const { status = 200 } = response;
  const data = await response.json();

  if (!data || !Object.keys(data).length) {
    return null;
  } else if (status === 200) {
    return data;
  } else {
    throw new Error(data.message);
  }
}

/**
 * Extracts the base path from a Fastify request's route configuration.
 *
 * This internal function is used to determine the mount path for Auth.js
 * routes by parsing the route URL pattern and removing the wildcard suffix.
 *
 * @param req - The Fastify request object
 * @returns The base path string
 *
 * @internal
 */
function getBasePath(req: FastifyRequest): string {
  return req.routeOptions.config.url.split('/*')[0];
}
