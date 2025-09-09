import * as crypto from 'crypto';

export type DecryptedToken =
  & DecryptedTokenBase
  & DecryptedTokenEmail
  & DecryptedTokenIp;

export type DecryptedTokenBase = {
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
export type DecryptedTokenEmail =
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
export type DecryptedTokenIp =
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

/**
 * From official site: https://my.truesign.ai/docs
 * Decrypts token with encryptionKey and returns a JSON with the decrypted info 
 * @param encryptionKey string
 * @param token string 
 * @returns DecryptedToken 
 */
export function decryptTruesignToken(encryptionKey: string, token: string): DecryptedToken {
  const iv = token.substring(0, 16);
  const encryptedMsg = token.substring(16);
  const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, iv);
  let decryptedTxt = decipher.update(encryptedMsg, 'base64', 'utf8');
  decryptedTxt += decipher.final('utf8');
  return JSON.parse(decryptedTxt);
}

export type ShouldAcceptTokenFunction = (
  decryptedToken: DecryptedToken,
  options?: TruesignHookConfig,
) => boolean;

export interface TruesignHookConfig {
  encryptionKey: string;
  allowUnauthenticated: boolean;
  shouldAcceptToken: (
    decryptedToken: DecryptedToken,
    options?: TruesignHookConfig,
  ) => boolean;
  queryStringPath?: string;
  decryptFunction?: Function;
}

/**
 * Given a TruesignHookConfig, returns a Fastify hook function (request, response, callback) 
 * It injects tsToken in request to be available in next middlewares or route handler.
 * @param config TruesignHookConfig
 * @returns 
 */
export const getTruesignHook = (config: TruesignHookConfig) => (req: any, res: any, next: any) => {
  try {
    const queryPath = config.queryStringPath || 'ts-token';
    if (config.allowUnauthenticated || !config.encryptionKey) {
      return next();
    }
    const tsToken = req.query[queryPath];
    if (!tsToken) {
      return res.code(401).send();
    }
    const decryptedToken = (config.decryptFunction || decryptTruesignToken)(config.encryptionKey, tsToken);
    if (!config.shouldAcceptToken(decryptedToken, config)) {
      return res.code(401).send();
    }
    req[queryPath] = decryptedToken;
    next();
  } catch (error) {
    console.error(error);
    return res.code(401).send();
  }
};
