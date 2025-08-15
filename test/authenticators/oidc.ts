/**
 * authenticateOidc performs an authorization-code sign-in flow
 * against a configured OpenID Connect provider.
 */
import request from 'supertest';
import { URL } from 'url';
import type { TestUser } from '../test-app.js';

/**
 * Safely converts headers object to a typed record
 */
function asHeaderMap(
  headers: unknown,
): Record<string, string | string[] | undefined> {
  return (headers ?? {}) as Record<string, string | string[] | undefined>;
}

/**
 * Performs OAuth/OIDC authentication flow for testing purposes.
 *
 * This function simulates a complete OAuth authorization code flow:
 * 1. Gets CSRF token from the app
 * 2. Initiates sign-in with the OIDC provider
 * 3. Follows redirects to the mock IdP
 * 4. Posts credentials and claims to complete authentication
 * 5. Completes the callback to establish the session
 *
 * @param agent - SuperTest agent to maintain session state
 * @param who - Test user data for authentication
 * @throws {Error} If any step of the authentication flow fails
 */
export async function authenticateOidc(
  agent: ReturnType<typeof request.agent>,
  who: TestUser,
): Promise<void> {
  const baseUrl = 'http://127.0.0.1';

  // 1) Get CSRF token
  const csrfRes = await agent.get('/auth/csrf').expect(200);
  const csrfBody = (csrfRes.body ?? {}) as Partial<{ csrfToken: string }>;
  const csrfToken = csrfBody.csrfToken;
  if (!csrfToken) {
    throw new Error('Missing csrfToken (keycloak)');
  }

  // 2) Start sign-in flow
  const signInRes = await agent
    .post('/auth/signin/keycloak')
    .type('form')
    .send({ csrfToken, callbackUrl: '/' });

  if (signInRes.status < 300 || signInRes.status >= 400) {
    throw new Error(`Expected 3xx from signin, got ${signInRes.status}`);
  }

  const signInHeaders = asHeaderMap(signInRes.headers);
  const authorizeLocation = signInHeaders.location as string | undefined;
  if (!authorizeLocation) {
    throw new Error('Missing authorize Location');
  }

  const authorizeUrl = new URL(authorizeLocation, baseUrl).toString();

  let res = await fetch(authorizeUrl, { redirect: 'manual' });

  if (res.status === 200) {
    const loginBody = new URLSearchParams({
      username: who.email ?? who.name ?? who.id,
      claims: JSON.stringify({
        sub: who.id,
        preferred_username: who.id,
        name: who.name,
        email: who.email,
        roles: who.roles,
        realm_access: { roles: who.roles },
      }),
    });

    res = await fetch(res.url, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: loginBody,
    });
  }

  if (res.status < 300 || res.status >= 400) {
    throw new Error(`Expected redirect from login, got ${res.status}`);
  }

  // 5) Complete callback on the app
  const cbLocation = res.headers.get('location');
  if (!cbLocation) {
    throw new Error('Missing callback Location');
  }

  const { pathname, search } = new URL(cbLocation, authorizeUrl);
  await agent.get(`${pathname}${search}`).expect(302);
}
