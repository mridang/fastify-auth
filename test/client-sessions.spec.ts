// noinspection DuplicatedCode

/**
 * E2E: AuthModule matrix across provider type, cookie security, and user
 * actor. Uses a dynamic Nest module with both providers configured and a
 * mock OIDC server. Verifies route access, session payloads, exposed
 * providers, and CSRF cookie naming under secure and insecure cookies.
 *
 * Matrix:
 *   - Providers: Credentials, Keycloak (OIDC)
 *   - Cookies: Insecure (HTTP), Secure (HTTPS semantics for tests)
 *   - Actors: unauthenticated, user, admin
 *
 * The secure cookie behavior is simulated for HTTP by patching SuperAgent
 * so it will send `Secure` cookies. The patch is confined to this suite.
 */

import { expect } from '@jest/globals';
import request from 'supertest';
import { GenericContainer, StartedTestContainer, Wait } from 'testcontainers';
import { createTestApp, type TestUser } from './test-app.js';
import { authenticateCredentials } from './authenticators/credentials.js';
import { authenticateOidc } from './authenticators/oidc.js';
import './supertest-extensions.js';

let container: StartedTestContainer;
let oauthHost: string;
let appRef: Awaited<ReturnType<typeof createTestApp>> | null = null;

const TEST_USERS: Record<'admin' | 'user', TestUser> = {
  admin: {
    id: '1',
    name: 'Admin User',
    email: 'admin@example.com',
    roles: ['admin', 'user'],
    password: 'password',
  },
  user: {
    id: '2',
    name: 'Regular User',
    email: 'user@example.com',
    roles: ['user'],
    password: 'password',
  },
};

beforeAll(async () => {
  container = await new GenericContainer(
    'ghcr.io/navikt/mock-oauth2-server:2.1.10',
  )
    .withExposedPorts(8080)
    .withWaitStrategy(Wait.forHttp('/', 8080).forStatusCode(405))
    .start();

  // noinspection HttpUrlsUsage
  oauthHost = `http://${container.getHost()}:${container.getMappedPort(8080)}`;
}, 60_000);

afterAll(async () => {
  if (container) {
    await container.stop();
  }
});

describe('AuthModule E2E matrix (providers x cookie modes x access matrix)', () => {
  [
    {
      label: 'Credentials provider',
      authenticate: async (
        agent: ReturnType<typeof request.agent>,
        who: TestUser,
      ): Promise<void> => {
        await authenticateCredentials(agent, who);
      },
    },
    {
      label: 'Keycloak provider',
      authenticate: async (
        agent: ReturnType<typeof request.agent>,
        who: TestUser,
      ): Promise<void> => {
        await authenticateOidc(agent, who);
      },
    },
  ].forEach(({ label: providerLabel, authenticate: authFn }) => {
    describe(providerLabel, () => {
      [
        {
          label: 'Insecure cookies (HTTP)',
          useSecureCookies: false,
        },
        {
          label: 'Secure cookies (HTTPS)',
          useSecureCookies: true,
        },
      ].forEach(({ label: cookieLabel, useSecureCookies }) => {
        describe(cookieLabel, () => {
          let originalEnv: string | undefined;

          beforeAll(async () => {
            originalEnv = process.env.TEST_SECURE_COOKIES;
            process.env.TEST_SECURE_COOKIES = String(useSecureCookies);

            appRef = await createTestApp({
              useSecureCookies,
              oauthIssuer: `${oauthHost}/default`,
              users: TEST_USERS,
              strategy: 'client',
            });

            await appRef.listen({ port: 0 });
          }, 60_000);

          afterAll(async () => {
            if (appRef) {
              await appRef.close();
            }
            appRef = null;

            if (originalEnv === undefined) {
              delete process.env.TEST_SECURE_COOKIES;
            } else {
              process.env.TEST_SECURE_COOKIES = originalEnv;
            }
          });

          /**
           * Ensures Auth.js exposes both configured providers so downstream
           * tests do not silently run with a misconfigured module.
           */
          test('auth providers endpoint exposes both providers', async () => {
            const res = await request(appRef!.server)
              .get('/auth/providers')
              .expect(200);

            expect(res.body).toEqual(
              expect.objectContaining({
                credentials: expect.objectContaining({
                  id: 'credentials',
                  type: 'credentials',
                }),
                keycloak: expect.objectContaining({
                  id: 'keycloak',
                  type: 'oidc',
                }),
              }),
            );
          });

          /**
           * Validates that the CSRF endpoint emits the correct cookie name
           * for secure vs. insecure cookie modes and sets the Secure flag
           * only when secure cookies are enabled.
           */
          test('csrf endpoint sets the correct cookie name', async () => {
            const expectedName = useSecureCookies
              ? '__Host-authjs.csrf-token'
              : 'authjs.csrf-token';

            await request(appRef!.server)
              .get('/auth/csrf')
              .expect(200)
              .expectCookie(expectedName, { secure: useSecureCookies });
          });

          [
            {
              label: 'Unauthenticated' as const,
              actor: 'unauth' as const,
              setup: async (): Promise<ReturnType<typeof request.agent>> => {
                return request.agent(appRef!.server);
              },
              expectedUser: null as
                | null
                | (typeof TEST_USERS)['user']
                | (typeof TEST_USERS)['admin'],
            },
            {
              label: 'Authenticated as Regular User' as const,
              actor: 'user' as const,
              setup: async (): Promise<ReturnType<typeof request.agent>> => {
                const agent = request.agent(appRef!.server);
                await authFn(agent, TEST_USERS.user);
                return agent;
              },
              expectedUser: TEST_USERS.user,
            },
            {
              label: 'Authenticated as Admin' as const,
              actor: 'admin' as const,
              setup: async (): Promise<ReturnType<typeof request.agent>> => {
                const agent = request.agent(appRef!.server);
                await authFn(agent, TEST_USERS.admin);
                return agent;
              },
              expectedUser: TEST_USERS.admin,
            },
          ].forEach(({ label: scenarioLabel, actor, setup, expectedUser }) => {
            describe(scenarioLabel, () => {
              let agent: ReturnType<typeof request.agent>;

              beforeAll(async () => {
                agent = await setup();
              });

              if (actor === 'unauth') {
                /**
                 * Public endpoints should be accessible without authentication to allow
                 * basic functionality for anonymous users.
                 */
                test('public endpoint allows access', async () => {
                  await agent.get('/public').expect(200);
                });

                /**
                 * Session info should be accessible to all users (authenticated and
                 * unauthenticated) to allow UI components to determine auth state.
                 */
                test('session info endpoint allows access', async () => {
                  await agent.get('/session-info').expect(200);
                });

                /**
                 * User profile requires authentication to protect private user data.
                 * Unauthenticated requests should be rejected with 401.
                 */
                test('profile endpoint requires authentication', async () => {
                  await agent.get('/profile').expect(401);
                });

                /**
                 * User settings contain sensitive configuration and require authentication
                 * to prevent unauthorized access or modification.
                 */
                test('user settings endpoint requires authentication', async () => {
                  await agent.get('/user/settings').expect(401);
                });

                /**
                 * Admin dashboard contains privileged information and should reject
                 * unauthenticated requests before checking role permissions.
                 */
                test('admin dashboard endpoint requires authentication', async () => {
                  await agent.get('/admin/dashboard').expect(401);
                });

                /**
                 * Staff area requires authentication as the first barrier before any
                 * role-based access control can be applied.
                 */
                test('staff area endpoint requires authentication', async () => {
                  await agent.get('/staff/area').expect(401);
                });

                /**
                 * Auth session endpoint should be accessible to allow checking current
                 * authentication state without requiring prior authentication.
                 */
                test('auth session endpoint allows access', async () => {
                  await agent.get('/auth/session').expect(200);
                });

                /**
                 * Auth login endpoint must be accessible to unauthenticated users to
                 * initiate the authentication flow.
                 */
                test('auth login endpoint allows access', async () => {
                  await agent.get('/auth/login').expect(200);
                });
              } else if (actor === 'user') {
                /**
                 * Public endpoints should remain accessible to authenticated users to
                 * ensure consistent behavior across authentication states.
                 */
                test('public endpoint allows access', async () => {
                  await agent.get('/public').expect(200);
                });

                /**
                 * Session info should provide user details for authenticated users to
                 * enable personalized UI and user context.
                 */
                test('session info endpoint allows access', async () => {
                  await agent.get('/session-info').expect(200);
                });

                /**
                 * Regular users should be able to access their own profile information
                 * once authenticated.
                 */
                test('profile endpoint allows access', async () => {
                  await agent.get('/profile').expect(200);
                });

                /**
                 * Authenticated users should be able to view and modify their personal
                 * settings and preferences.
                 */
                test('user settings endpoint allows access', async () => {
                  await agent.get('/user/settings').expect(200);
                });

                /**
                 * Admin dashboard requires admin role privileges. Regular users should
                 * be rejected with 403 (forbidden) rather than 401 (unauthorized).
                 */
                test('admin dashboard endpoint requires admin role', async () => {
                  await agent.get('/admin/dashboard').expect(403);
                });

                /**
                 * Staff area requires elevated privileges beyond basic user role.
                 * Should return 403 to indicate insufficient permissions.
                 */
                test('staff area endpoint requires admin role', async () => {
                  await agent.get('/staff/area').expect(403);
                });

                /**
                 * Auth session should continue to work for authenticated users to
                 * maintain session state and enable session management.
                 */
                test('auth session endpoint allows access', async () => {
                  await agent.get('/auth/session').expect(200);
                });

                /**
                 * Auth login should remain accessible to authenticated users to allow
                 * account switching or re-authentication if needed.
                 */
                test('auth login endpoint allows access', async () => {
                  await agent.get('/auth/login').expect(200);
                });
              } else {
                /**
                 * Admins should retain access to public endpoints to ensure they can
                 * use all application features without privilege restrictions.
                 */
                test('public endpoint allows access', async () => {
                  await agent.get('/public').expect(200);
                });

                /**
                 * Admin users should have access to session info with their complete
                 * role information and elevated privileges reflected.
                 */
                test('session info endpoint allows access', async () => {
                  await agent.get('/session-info').expect(200);
                });

                /**
                 * Admins should be able to access their profile information just like
                 * regular users, with potential additional admin-specific data.
                 */
                test('profile endpoint allows access', async () => {
                  await agent.get('/profile').expect(200);
                });

                /**
                 * Admin users should have full access to user settings, potentially
                 * with additional administrative configuration options.
                 */
                test('user settings endpoint allows access', async () => {
                  await agent.get('/user/settings').expect(200);
                });

                /**
                 * Admin dashboard should be fully accessible to users with admin role,
                 * providing administrative controls and system oversight.
                 */
                test('admin dashboard endpoint allows access', async () => {
                  await agent.get('/admin/dashboard').expect(200);
                });

                /**
                 * Staff area should be accessible to admin users as they have the
                 * highest level of privileges in the system.
                 */
                test('staff area endpoint allows access', async () => {
                  await agent.get('/staff/area').expect(200);
                });

                /**
                 * Auth session should work normally for admin users to maintain their
                 * session state and role information.
                 */
                test('auth session endpoint allows access', async () => {
                  await agent.get('/auth/session').expect(200);
                });

                /**
                 * Auth login should remain accessible to admin users for account
                 * management and potential re-authentication scenarios.
                 */
                test('auth login endpoint allows access', async () => {
                  await agent.get('/auth/login').expect(200);
                });
              }

              /**
               * Validates that session info endpoint returns the correct payload structure
               * and user data. For unauthenticated users, should return hasSession: false
               * and user: null. For authenticated users, should include complete user
               * details (id, email, roles, name) for UI personalization.
               */
              test('session info endpoint returns expected user payload', async () => {
                const res = await agent.get('/session-info').expect(200);

                if (!expectedUser) {
                  expect(res.body.hasSession).toBe(false);
                  expect(res.body.user).toBeNull();
                } else {
                  expect(res.body.hasSession).toBe(true);
                  expect(res.body.user).toMatchObject({
                    id: expectedUser.id,
                    email: expectedUser.email,
                    roles: expectedUser.roles,
                    name: expectedUser.name,
                  });
                }
              });

              /**
               * Validates Auth.js session endpoint behavior. Should return null for
               * unauthenticated requests and complete session object with user details
               * for authenticated requests. This is the standard Auth.js session format.
               */
              test('auth session endpoint returns expected payload', async () => {
                const res = await agent.get('/auth/session').expect(200);

                if (!expectedUser) {
                  expect(res.body).toBeNull();
                } else {
                  expect(res.body.user).toMatchObject({
                    id: expectedUser.id,
                    email: expectedUser.email,
                    roles: expectedUser.roles,
                    name: expectedUser.name,
                  });
                }
              });

              /**
               * Verifies that browser requests (indicated by HTML Accept headers) to
               * protected resources trigger a redirect to the sign-in page with the
               * original URL preserved as a callback parameter for post-login redirect.
               */
              test('unauthenticated browser requests redirect to sign-in page', async () => {
                const agent = request.agent(appRef!.server);

                await agent
                  .get('/profile')
                  .set(
                    'Accept',
                    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                  )
                  .expectRedirectTo('/auth/signin?callbackUrl=%2Fprofile');
              });

              /**
               * Ensures that API requests (non-browser, typically JSON) to protected
               * resources return proper 401 JSON error responses instead of redirects.
               * This allows API clients to handle authentication failures appropriately.
               */
              test('unauthenticated API requests are rejected', async () => {
                const agent = request.agent(appRef!.server);

                await agent
                  .get('/profile')
                  .expect(401)
                  .expect('Content-Type', /json/)
                  .expect({
                    message: 'No user found in session',
                    error: 'Unauthorized',
                    statusCode: 401,
                  });
              });
            });
          });
        });
      });
    });
  });
});
