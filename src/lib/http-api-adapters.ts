import type { FastifyRequest, FastifyReply } from 'fastify';
import qs from 'qs';

type RequestBody = string | Buffer;

/**
 * Converts a framework-specific request (Fastify) into a
 * standard Web API `Request` object using the same logic as NestJS version.
 */
function encodeRequestBody(req: FastifyRequest): RequestBody | undefined {
  const contentType = req.headers['content-type'];
  const method = req.method;

  let body: RequestBody | undefined;

  if (!/GET|HEAD/.test(method.toUpperCase())) {
    const rawBody = req.body;

    if (rawBody !== undefined && rawBody !== null) {
      if (contentType?.includes('application/x-www-form-urlencoded')) {
        body = qs.stringify(rawBody as Record<string, unknown>, {
          arrayFormat: 'repeat',
        });
      } else if (contentType?.includes('application/json')) {
        body = JSON.stringify(rawBody);
      } else if (typeof rawBody === 'string') {
        body = rawBody;
      } else if (Buffer.isBuffer(rawBody)) {
        body = rawBody;
      } else if (typeof rawBody === 'object') {
        // Fallback for object bodies without a proper content-type.
        body = qs.stringify(rawBody as Record<string, unknown>, {
          arrayFormat: 'repeat',
        });
      }
    }
  }

  return body;
}

/**
 * Converts a Fastify Request object to a Web API Request object.
 *
 * This adapter function handles the conversion between Fastify's request
 * format and the standard Web API Request interface used by Auth.js core.
 * It preserves headers, method, URL, and body content while ensuring
 * proper encoding based on content type using the qs library.
 *
 * @param req - The Fastify request object to convert
 * @returns A Web API Request object
 *
 * @example
 * ```ts
 * fastify.route({
 *   method: "POST",
 *   url: "/api/auth/*",
 *   handler: async (request, reply) => {
 *     const webRequest = toWebRequest(request)
 *     const response = await Auth(webRequest, config)
 *     return toFastifyReply(response, reply)
 *   }
 * })
 * ```
 */
export function toWebRequest(req: FastifyRequest): Request {
  const url = `${req.protocol}://${req.host}${req.originalUrl}`;
  const headers = new Headers();

  Object.entries(req.headers).forEach(([key, value]) => {
    if (Array.isArray(value)) {
      value.forEach((v) => {
        if (v) {
          headers.append(key, v);
        }
      });
    } else if (value) {
      headers.append(key, value);
    }
  });

  const rawBody = /GET|HEAD/.test(req.method)
    ? undefined
    : encodeRequestBody(req);

  const body =
    rawBody && Buffer.isBuffer(rawBody) ? new Uint8Array(rawBody) : rawBody;

  return new Request(url, {
    method: req.method,
    headers,
    body,
  });
}

/**
 * Converts a Web API Response object to a Fastify reply.
 *
 * This adapter function handles the conversion from Auth.js core's Web API
 * Response format back to Fastify's reply interface. It transfers headers,
 * status codes, and body content appropriately.
 *
 * @param response - The Web API Response object to convert
 * @param reply - The Fastify reply object to populate
 * @returns Promise resolving to the response body text
 *
 * @example
 * ```ts
 * fastify.route({
 *   method: ["GET", "POST"],
 *   url: "/api/auth/*",
 *   handler: async (request, reply) => {
 *     const webRequest = toWebRequest(request)
 *     const webResponse = await Auth(webRequest, config)
 *     return toFastifyReply(webResponse, reply)
 *   }
 * })
 * ```
 */
export async function toFastifyReply(
  response: Response,
  reply: FastifyReply,
): Promise<string> {
  response.headers.forEach((value, key) => {
    if (value) {
      reply.header(key, value);
    }
  });

  reply.status(response.status);

  return await response.text();
}
