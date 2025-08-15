/**
 * Test application factory for Fastify Auth.js e2e testing.
 *
 * Creates a configured Fastify application instance with Auth.js integration
 * and test routes. Supports both client-side (JWT) and server-side (database)
 * session strategies with configurable cookie security.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import Fastify from 'fastify';
import type { Session } from '@auth/core/types';
// noinspection ES6PreferShortImport
import {
  FastifyAuth,
  type FastifyAuthConfig,
  getSession,
} from '../src/index.js';
import { createCredentialsProvider } from './providers/credential.js';
import { createKeycloakProvider } from './providers/keycloak.js';
import { MemoryAdapter } from './memory.adapter.js';

/**
 * Test user interface matching the NestJS test suite
 */
export interface TestUser {
  id: string;
  name: string;
  email: string;
  roles: string[];
  password?: string;
}

/**
 * Configuration options for the test application
 */
export interface TestAppOptions {
  useSecureCookies: boolean;
  oauthIssuer: string;
  users: Record<string, TestUser>;
  strategy?: 'client' | 'database';
}

/**
 * Extended session type for role-based testing
 */
interface TestSession extends Session {
  user: Session['user'] & {
    roles?: string[];
  };
}

/**
 * Augment Fastify reply to include session property
 */
declare module 'fastify' {
  // noinspection JSUnusedGlobalSymbols
  interface FastifyReply {
    // @ts-expect-error since this is a test app, we can ignore the type error
    session: TestSession | null;
  }
}

declare module '@auth/core/types' {
  // noinspection JSUnusedGlobalSymbols
  interface User {
    roles: string[];
    customId?: string;
  }
}

declare module '@auth/core/adapters' {
  // noinspection JSUnusedGlobalSymbols
  interface AdapterUser {
    roles: string[];
    customId: string;
  }
}

/**
 * Authentication hook that retrieves the session and stores it on the reply
 */
async function authHook(
  request: FastifyRequest,
  reply: FastifyReply,
  config: FastifyAuthConfig,
): Promise<void> {
  try {
    reply.session = (await getSession(request, config)) as TestSession | null;
  } catch (error) {
    console.error('Error in authHook:', error);
    reply.session = null;
  }
}

/**
 * Authorization hook that requires authentication
 */
async function requireAuth(
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  if (!reply.session?.user) {
    const accept = request.headers.accept || '';

    if (accept.includes('text/html')) {
      const callbackUrl = encodeURIComponent(request.url);
      // Just pass the URL, 302 is the default
      return reply.redirect(`/auth/signin?callbackUrl=${callbackUrl}`);
    } else {
      return reply.status(401).send({
        message: 'No user found in session',
        error: 'Unauthorized',
        statusCode: 401,
      });
    }
  }
}

/**
 * Authorization hook that requires specific roles
 */
function requireRoles(...roles: string[]) {
  return async function (
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    await requireAuth(request, reply);

    if (reply.sent) {
      return;
    }

    const session = reply.session as TestSession;
    const userRoles = session?.user?.roles || [];
    const hasRole = roles.some((role) => userRoles.includes(role));

    if (!hasRole) {
      return reply.status(403).send({
        message: 'Insufficient permissions',
        error: 'Forbidden',
        statusCode: 403,
      });
    }
  };
}

/**
 * Creates a test Fastify application with Auth.js configuration
 *
 * @param options - Test application configuration
 * @returns Configured Fastify instance ready for testing
 */
export async function createTestApp(
  options: TestAppOptions,
): Promise<FastifyInstance> {
  const { useSecureCookies, oauthIssuer, users, strategy = 'client' } = options;

  const fastify = Fastify({
    trustProxy: true,
    logger: false,
  });

  fastify.decorateReply('session', null);

  const authConfig: FastifyAuthConfig = {
    secret:
      strategy === 'client'
        ? 'a-super-secret-for-testing'
        : 'server-sessions-test-secret',
    trustHost: true,
    useSecureCookies,
    providers:
      strategy === 'client'
        ? [
            createCredentialsProvider(users),
            createKeycloakProvider({
              issuer: oauthIssuer,
              clientId: 'client1',
              clientSecret: 'secret1',
            }),
          ]
        : [
            createKeycloakProvider({
              issuer: oauthIssuer,
              clientId: 'client1',
              clientSecret: 'secret1',
            }),
          ],
    callbacks: {},
  };

  if (strategy === 'database') {
    authConfig.adapter = MemoryAdapter();
    authConfig.session = {
      strategy: 'database',
      maxAge: 30 * 24 * 60 * 60,
    };

    authConfig.callbacks!.session = async ({ session, user }) => {
      if (user) {
        session.user = {
          ...session.user,
          id: (user as { customId?: string }).customId || user.id,
          email: user.email,
          name: user.name,
          roles: (user as { roles?: string[] }).roles || [],
        };
      }
      return session;
    };
  } else {
    // Client strategy - JWT + session callbacks
    authConfig.callbacks!.jwt = async ({
      token,
      user,
      account,
      profile,
      trigger,
    }) => {
      if (trigger === 'signIn' && user) {
        const userWithRoles = user as { roles?: string[] };
        token.roles = userWithRoles.roles;

        switch (account?.provider) {
          case 'keycloak': {
            const kcProfile = profile as { preferred_username?: string };
            token.sub = kcProfile.preferred_username;
            break;
          }
          case 'credentials': {
            token.sub = user.id;
            break;
          }
        }
      }
      return token;
    };

    authConfig.callbacks!.session = async ({ session, token }) => {
      const tokenWithRoles = token as { sub?: string; roles?: string[] };

      if (session.user) {
        const mutableUser = session.user as {
          id?: string;
          roles?: string[];
        };

        if (typeof tokenWithRoles.sub === 'string') {
          mutableUser.id = tokenWithRoles.sub;
        }
        mutableUser.roles = tokenWithRoles.roles ?? [];
      }
      return session;
    };
  }

  await fastify.register(FastifyAuth(authConfig), { prefix: '/auth' });

  fastify.addHook('preHandler', async (request, reply) => {
    await authHook(request, reply, authConfig);
  });

  fastify.get('/public', async () => {
    return {
      message: 'This is a public endpoint',
      timestamp: Date.now(),
    };
  });

  fastify.get(
    '/session-info',
    async (_request: FastifyRequest, reply: FastifyReply) => {
      const session = reply.session as TestSession;
      return {
        hasSession: !!session,
        user: session?.user || null,
        message: 'Session info (public)',
      };
    },
  );

  fastify.get(
    '/profile',
    {
      preHandler: requireAuth,
    },
    async (_request: FastifyRequest, reply: FastifyReply) => {
      const session = reply.session as TestSession;
      return {
        user: session?.user,
        expires: session?.expires,
        message: 'Profile data',
      };
    },
  );

  fastify.get(
    '/user/settings',
    {
      preHandler: requireRoles('user'),
    },
    async (_request: FastifyRequest, reply: FastifyReply) => {
      const session = reply.session as TestSession;
      return {
        user: session?.user,
        message: 'User settings page',
        userAccess: true,
      };
    },
  );

  fastify.get(
    '/admin/dashboard',
    {
      preHandler: requireRoles('admin'),
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const session = reply.session as TestSession;
      return {
        user: session?.user,
        message: 'Welcome to the admin dashboard',
        adminOnly: true,
      };
    },
  );

  fastify.get(
    '/staff/area',
    {
      preHandler: requireRoles('admin', 'moderator'),
    },
    async (_request: FastifyRequest, reply: FastifyReply) => {
      const session = reply.session as TestSession;
      return {
        user: session?.user,
        message: 'Staff only area',
        staffAccess: true,
      };
    },
  );

  fastify.get('/auth/login', async () => {
    return {
      page: 'custom-login',
      ok: true,
    };
  });

  return fastify;
}
