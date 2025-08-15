# Fastify Auth.js

A [Fastify](https://fastify.dev/) integration for [Auth.js](https://authjs.dev/)
that provides seamless authentication with multiple providers, session
management, and route protection using Fastify patterns.

This integration brings the power and flexibility of Auth.js to Fastify
applications with full TypeScript support, efficient HTTP handling,
and Fastify-native patterns including hooks, decorators, and plugins.

### Why?

Modern web applications require robust, secure, and flexible authentication
systems. While Auth.js provides excellent authentication capabilities,
integrating it with Fastify applications requires careful consideration of
framework patterns, plugin architecture, and TypeScript integration.

However, a direct integration isn't always straightforward. Different types
of applications or deployment scenarios might warrant different approaches:

- **Framework Integration:** Auth.js operates at the HTTP level, while Fastify
  uses plugins, hooks, and decorators. A proper integration should bridge this
  gap by providing Fastify-native patterns for authentication and authorization
  while maintaining the full Auth.js ecosystem compatibility.
- **HTTP Request Handling:** Fastify's optimized request/reply cycle requires
  efficient conversion between Fastify's request format and Web API standards.
  Teams need a unified approach that maintains performance while providing
  seamless Auth.js integration.
- **Session and Request Lifecycle:** Proper session handling in Fastify
  requires integration with the request lifecycle, hooks, and decorators.
  Manual integration often leads to inconsistent session management or
  improper request handling across different routes.
- **Route Protection:** Many applications need fine-grained authorization
  beyond simple authentication. This requires seamless integration between
  Auth.js user data and Fastify authorization patterns.

This integration, `@auth/fastify`, aims to provide the flexibility to
handle such scenarios. It allows you to leverage the full Auth.js ecosystem
while maintaining Fastify best practices, ultimately leading to a more
effective and less burdensome authentication implementation.

## Installation

Install using NPM by using the following command:

```sh
npm install @auth/fastify @auth/core
```

## Usage

To use this integration, add `FastifyAuth` plugin to your Fastify application.
The plugin provides authentication infrastructure with configurable
routes, middleware, and decorators.

You'll need to configure it with your Auth.js providers and options. The
integration will then be available throughout your application via Fastify's
plugin system.

First, add the plugin to your Fastify app:

```typescript
import Fastify from 'fastify';
import { FastifyAuth } from '@auth/fastify';
import GoogleProvider from '@auth/core/providers/google';

const fastify = Fastify({
  trustProxy: true, // Enable if behind a proxy
});

await fastify.register(
  FastifyAuth({
    providers: [
      GoogleProvider({
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      }),
    ],
    secret: process.env.AUTH_SECRET,
    trustHost: true,
  }),
  { prefix: '/auth' },
);
```

#### Using the Authentication System

The integration provides several functions and hooks for handling
authentication:

**Functions and Hooks:**

- `getSession()`: Retrieves the current Auth.js session from requests
- `authenticatedUser`: Hook that requires authentication for routes
- `requireRole()`: Hook that restricts access to users with specific roles
- `reply.session`: Decorated session data available in routes (optional)

**Basic Usage:**

```typescript
import { getSession } from '@auth/fastify';
import type { Session } from '@auth/core/types';

// Public route - no authentication needed
fastify.get('/api/public', async (request, reply) => {
  return { message: 'Public endpoint' };
});

// Protected route - manual session check
fastify.get('/api/profile', async (request, reply) => {
  const session = await getSession(request, authConfig);

  if (!session) {
    reply.status(401).send({ error: 'Unauthorized' });
    return;
  }

  return {
    user: session.user,
    expires: session.expires,
  };
});

// Protected route using preHandler hook
async function authenticatedUser(request, reply) {
  const session = await getSession(request, authConfig);
  if (!session?.user) {
    reply.redirect('/auth/signin?error=SessionRequired');
  }
}

fastify.get(
  '/api/admin',
  { preHandler: authenticatedUser },
  async (request, reply) => {
    return { adminData: true };
  },
);
```

##### Example: Advanced Configuration with Multiple Providers

This example shows how to use the plugin with multiple Auth.js
providers and custom session configuration:

```typescript
import Fastify from 'fastify';
import { FastifyAuth, getSession } from '@auth/fastify';
import GoogleProvider from '@auth/core/providers/google';
import GitHubProvider from '@auth/core/providers/github';

const fastify = Fastify({ trustProxy: true });

await fastify.register(
  FastifyAuth({
    providers: [
      GoogleProvider({
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      }),
      GitHubProvider({
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
      }),
    ],
    secret: process.env.AUTH_SECRET,
    trustHost: true,
    session: {
      strategy: 'jwt',
      maxAge: 30 * 24 * 60 * 60, // 30 days
    },
    callbacks: {
      jwt: async ({ token, user }) => {
        if (user) {
          token.roles = user.roles;
        }
        return token;
      },
      session: async ({ session, token }) => {
        session.user.roles = token.roles as string[];
        return session;
      },
    },
  }),
  { prefix: '/auth' },
);

// Decorate reply with session for performance
fastify.decorateReply('session', null);

// Global session attachment
fastify.addHook('preHandler', async (request, reply) => {
  reply.session = await getSession(request, authConfig);
});

// Role-based access control
async function requireRoles(...roles: string[]) {
  return async function (request, reply) {
    if (!reply.session) {
      reply.session = await getSession(request, authConfig);
    }

    const userRoles = reply.session?.user?.roles || [];
    const hasRole = roles.some((role) => userRoles.includes(role));

    if (!hasRole) {
      reply.status(403).send({ error: 'Insufficient permissions' });
    }
  };
}

// Routes with different protection levels
fastify.get('/api/user', async (request, reply) => {
  if (!reply.session) {
    reply.status(401).send({ error: 'Not authenticated' });
    return;
  }
  return reply.session.user;
});

fastify.get(
  '/api/admin',
  { preHandler: requireRoles('admin') },
  async (request, reply) => {
    return { adminData: true };
  },
);
```

## Known Issues

- **Plugin Registration Order:** The integration automatically registers
  `@fastify/formbody` plugin for form parsing. If you need custom form
  parsing, register your parser before the Auth.js plugin.
- **Session Storage Configuration:** The integration relies on Auth.js
  session handling mechanisms. When configuring custom session storage or
  database adapters, ensure they are properly configured in the Auth.js
  options passed to the plugin.
- **Role-Based Authorization:** The role-based hooks expect user roles to be
  available in the `session.user.roles` array. Ensure your Auth.js callbacks
  (particularly `jwt` and `session` callbacks) properly populate this field
  from your authentication provider or database.
- **Type Augmentation:** The integration supports augmenting Fastify request
  and reply types with session properties. For custom user properties beyond
  the default Auth.js user schema, you'll need to extend the Auth.js types
  in your application.

## Useful links

- **[Auth.js](https://authjs.dev/):** The authentication library that this
  integration is built upon.
- **[Fastify](https://fastify.dev/):** The Node.js framework this integration
  is designed for.
- **[Auth.js Providers](https://authjs.dev/getting-started/providers):**
  Complete list of supported authentication providers.

## Contributing

If you have suggestions for how this integration could be improved, or
want to report a bug, open an issue - we'd love all and any
contributions.

## License

ISC © 2024 Auth.js Team
