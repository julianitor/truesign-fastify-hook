import * as crypto from 'node:crypto';

export type DecryptedToken =
  & DecryptedTokenBase
  & DecryptedTokenEmail
  & DecryptedTokenIp;

type DecryptedTokenBase = {
  /**
   * `true` if the interaction is launched by a scripting or automated tool -- not a human.
   *
   * Modern automated browsers are only detected when calling the endpoint from Truesign's `<script>` or using the
   * Botwall.
   */
  bot: boolean;
  /**
   * `true` if your visitor is using a VPN, proxy or the Tor network.
   */
  anonymizer: boolean;
  /**
   * A cluster is a distributed attack triggered by a single actor.
   *
   * Truesign can detect and link different requests to a single cluster. This field is `null` if the request doesn't
   * belong to any cluster.
   */
  clusterId: string;

  // identifiers
  /**
   * Number in range (0 -- 2^53). Each token contains a different value.
   *
   * Avoid visitors reusing tokens by keeping track of what uniqueKeys you've seen in the last N minutes.
   */
  uniqueKey: number,
  /**
   * The token creation time as Unix epoch with millisecond resolution.
   *
   * Avoid visitors reusing tokens by rejecting timestamps older than N minutes.
   */
  timestamp: number,
  /**
   * [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) country codes, plus:
   * - `XK` as an internationally agreed temporary code for Kosovo.
   * - `unknown` in case the country cannot be determined from the IP.
   */
  country: string,
};

/**
 * Only added if an email or domain was passed on the request.
 */
type DecryptedTokenEmail =
  | {
    /**
     * The email you passed for Truesign to verify on this request.
     */
    email: string,
    /**
     * `true` if the email belongs to a temporary email service.
     */
    disposable: boolean,
    /**
     * `true` if the domain doesn't provide mail services, or (if doing deep email validation) the email address doesn't
     * exist on this email service.
     */
    notDeliverable: boolean,
    /**
     * Only present when the email domain doesn't exist but it resembles an existing email service. In that case, it
     * contains the correct domain name.
     *
     * For example if the user inputs "gmai.com" the token will contain `"typo": "gmail.com"`.
     */
    typo: string,
  }
  | {
    email?: never,
    disposable?: never,
    notDeliverable?: never,
    typo?: never,
  };

/** Your user's IP. */
type DecryptedTokenIp =
  | {
    /** Your user's IPv4. */
    ipv4: string;
  }
  | {
    /**
     * Your user's IPv6 in expanded format.
     */
    ipv6: string;
  };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Generates a function that extracts the Truesign token from a query string param.
 *
 * @param queryParam Query param name where the token is expected to be found (case-sensitive)
 * @returns A function that extracts the token from the request
 */
export function extractTruesignTokenFromQuery(
  queryParam: string,
): ExtractTokenFunction {
  return (req: FastifyRequest) => {
    if (!isRecord(req.query)) {
      return null;
    }

    const tsToken = req.query[queryParam];
    if (typeof tsToken !== 'string' || !tsToken) {
      return null;
    }

    return tsToken;
  };
}

/**
 * Generates a function that extracts the Truesign token from a header.
 *
 * @param headerName Header name where the token is expected to be found (case-insensitive)
 * @returns A function that extracts the token from the request
 */
export function extractTruesignTokenFromHeader(
  headerName: string,
): ExtractTokenFunction {
  const headerNameLower = headerName.toLowerCase();

  return (req: FastifyRequest) => {
    const tsToken = req.headers[headerNameLower];
    // This explicitly excludes string[] because we wouldn't be sure _which_ of the headers to use
    if (typeof tsToken !== 'string' || !tsToken) {
      return null;
    }

    return tsToken;
  };
}

type ExtractTrueSignTokenOptions = {
  queryParam?: string;
  headerName?: string;
};

const DEFAULT_EXTRACT_QUERY_PARAM = 'ts-token';
const DEFAULT_EXTRACT_HEADER_NAME = 'x-ts-token';

/**
 * Default Truesign token extraction function.
 *
 * Extracts the Truesign token from either a query parameter or a header.
 *
 * @param queryParam Query param name where the token is expected to be found (case-sensitive)
 * @param headerName Header name where the token is expected to be found (case-insensitive)
 * @returns A function that extracts the token from the request
 */
export function extractTrueSignToken(options: ExtractTrueSignTokenOptions = {}): ExtractTokenFunction {
  const {
    queryParam = DEFAULT_EXTRACT_QUERY_PARAM,
    headerName = DEFAULT_EXTRACT_HEADER_NAME,
  } = options;

  const extractFromQuery = extractTruesignTokenFromQuery(queryParam);
  const extractFromHeader = extractTruesignTokenFromHeader(headerName);

  return (req: FastifyRequest) => {
    return extractFromQuery(req) ?? extractFromHeader(req);
  };
}

/**
 * Decrypts token with encryptionKey and returns a JSON with the decrypted info.
 *
 * If the token is invalid or decryption fails, it returns `null`.
 *
 * @see https://my.truesign.ai/docs
 * @param encryptionKey string
 * @param token string
 * @returns DecryptedToken or `null` if decryption failed
 */
export function decryptTruesignToken(encryptionKey: string, token: string): DecryptedToken | null {
  const IV_LENGTH = 16; // For AES-256-CBC, this is always 16

  if (token.length < IV_LENGTH) {
    return null;
  }

  try {
    const iv = token.substring(0, IV_LENGTH);
    const encryptedMsg = token.substring(IV_LENGTH);
    const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, iv);
    let decryptedTxt = decipher.update(encryptedMsg, 'base64', 'utf8');
    decryptedTxt += decipher.final('utf8');

    // Here we assume that the decrypted text conforms to DecryptedToken, which should be true since only Truesign
    // could have generated it.
    return JSON.parse(decryptedTxt) as DecryptedToken;
  } catch (error) {
    // Since Truesign tokens are user-controlled input, decryption can fail for many reasons (invalid base64, invalid
    // iv, invalid json...)
    // We log the error for debugging purposes, but we don't throw to avoid breaking the request flow.
    console.warn('Error decrypting Truesign token:', error);
    return null;
  }
}

export type ShouldAcceptTokenFunction<AdditionalConfig extends Record<string, unknown> = {}> = (
  decryptedToken: DecryptedToken,
  options: TruesignHookConfig<AdditionalConfig>,
) => boolean;

export type ExtractTokenFunction = (
  req: FastifyRequest,
) => string | null;

export type DecryptTokenFunction = (
  encryptionKey: string,
  token: string,
) => DecryptedToken | null;

/**
 * Configuration object for the Truesign Fastify hook.
 *
 * {@link Additional} can be used to extend the config with custom properties.
 */
export type TruesignHookConfig<Additional extends Record<string, unknown> = {}> =
  & {
    /**
     * Token encryption key, as listed in your [Truesign dashboard](https://my.truesign.ai/dashboard#endpoints).
     */
    encryptionKey: string;
    /**
     * If `true`, the hook will allow all requests, completely bypassing the hook.
     */
    allowUnauthenticated?: boolean;
    /**
     * A function that receives the decrypted token and returns whether the token should be accepted.
     *
     * It receives the decrypted token and the full config object as parameters, so you can use other config values in
     * your logic.
     *
     * @default `() => true`
     */
    shouldAcceptToken?: ShouldAcceptTokenFunction<Additional>;
    /**
     * Function that extracts the token from the {@link FastifyRequest}.
     *
     * @default
     * ```
     * extractTrueSignToken({
     *   queryParam: 'ts-token',
     *   headerName: 'x-ts-token',
     * })
     * ```
     */
    extractToken?: ExtractTokenFunction;
    /**
     * The key where the decrypted token is injected in {@link FastifyRequest} for later middlewares or route handler.
     *
     * @default 'ts-token'
     */
    injectInto?: string;
    /**
     * Custom decrypt function.
     *
     * @default decryptTruesignToken
     */
    decryptFunction?: DecryptTokenFunction;
  }
  & Additional;

/**
 * Returns a Fastify hook that validates Truesign tokens and injects the decrypted token in the request.
 *
 * @param config TruesignHookConfig
 * @returns Fastify hook function
 */
export function getTruesignHook<AdditionalConfig extends Record<string, unknown> = {}>(
  config: TruesignHookConfig<AdditionalConfig>
): (req: FastifyRequest, res: FastifyReply, next: HookHandlerDoneFunction) => void {
  if (config.allowUnauthenticated) {
    return (_req, _res, next) => {
      next();
    };
  }

  if (!config.encryptionKey) {
    throw new Error('`encryptionKey` is required when `allowUnauthenticated` is false');
  }

  const shouldAcceptToken = config.shouldAcceptToken ?? (() => true);
  const extractToken = config.extractToken ?? extractTrueSignToken();
  const decryptFunction = config.decryptFunction ?? decryptTruesignToken;
  const injectInto = config.injectInto || 'ts-token';

  return (req, res, next) => {
    try {
      if (!isRecord(req.query)) {
        throw new Error('`req.query` is not a record');
      }

      const tsToken = extractToken(req);
      if (typeof tsToken !== 'string' || !tsToken) {
        return res.code(401).send();
      }

      const decryptedToken = decryptFunction(config.encryptionKey, tsToken);
      if (decryptedToken === null || !shouldAcceptToken(decryptedToken, config)) {
        return res.code(401).send();
      }

      // @todo Figure out a better way to inject this in the request without type casting
      //       It's not clear how decorator typing works inside hooks
      (req as unknown as Record<string, unknown>)[injectInto] = decryptedToken;
      next();
    } catch (error) {
      console.error(error);
      return res.code(401).send();
    }
  };
};
