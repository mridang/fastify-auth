import type { FastifyRequest, FastifyReply } from 'fastify';

/**
 * Type representing form data that can be encoded as URL-encoded string.
 * Values can be strings, numbers, booleans, or arrays of these types.
 */
type FormData = Record<
  string,
  string | number | boolean | (string | number | boolean)[]
>;

/**
 * Type representing JSON-serializable data.
 */
type JsonData = Record<string, unknown>;

/**
 * Encodes an object as a URL-encoded string suitable for form submission.
 *
 * Handles both single values and arrays by appending multiple entries for
 * array values. All values are converted to strings during encoding.
 *
 * @param object - The form data object to encode, defaults to empty object
 * @returns The URL-encoded string representation
 *
 * @example
 * ```typescript
 * const formData = { name: "John", tags: ["admin", "user"] }
 * const encoded = encodeUrlEncoded(formData)
 * // Returns: "name=John&tags=admin&tags=user"
 * ```
 */
export function encodeUrlEncoded(object: FormData = {}): string {
  const params = new URLSearchParams();

  for (const [key, value] of Object.entries(object)) {
    if (Array.isArray(value)) {
      value.forEach((v) => {
        params.append(key, String(v));
      });
    } else {
      params.append(key, String(value));
    }
  }

  return params.toString();
}

/**
 * Encodes an object as a JSON string.
 *
 * @param obj - The object to encode as JSON
 * @returns The JSON string representation
 *
 * @example
 * ```typescript
 * const data = { user: "john", active: true }
 * const json = encodeJson(data)
 * // Returns: '{"user":"john","active":true}'
 * ```
 */
function encodeJson(obj: JsonData): string {
  return JSON.stringify(obj);
}

/**
 * Encodes a Fastify request body based on the Content-Type header.
 *
 * Supports both URL-encoded form data and JSON payloads. The encoding
 * method is determined by examining the Content-Type header and the
 * body type.
 *
 * @param req - The Fastify request object containing the body to encode
 * @returns The encoded body string, or undefined if body cannot be encoded
 *
 * @example
 * ```typescript
 * const formRequest = {
 *   body: { name: "John" },
 *   headers: { "content-type": "application/x-www-form-urlencoded" }
 * }
 * const encoded = encodeRequestBody(formRequest)
 * ```
 */
function encodeRequestBody(req: FastifyRequest): string | undefined {
  const contentType = req.headers['content-type'];

  if (typeof req.body === 'object' && req.body !== null) {
    if (contentType?.includes('application/x-www-form-urlencoded')) {
      return encodeUrlEncoded(req.body as FormData);
    } else if (contentType?.includes('application/json')) {
      return encodeJson(req.body as JsonData);
    } else {
      return undefined;
    }
  } else if (typeof req.body === 'string') {
    return req.body;
  } else {
    return undefined;
  }
}

/**
 * Converts a Fastify Request object to a Web API Request object.
 *
 * This adapter function handles the conversion between Fastify's request
 * format and the standard Web API Request interface used by Auth.js core.
 * It preserves headers, method, URL, and body content while ensuring
 * proper encoding based on content type.
 *
 * @param req - The Fastify request object to convert
 * @returns A Web API Request object
 *
 * @example
 * ```typescript
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

  const body = /GET|HEAD/.test(req.method) ? undefined : encodeRequestBody(req);

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
 * ```typescript
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
