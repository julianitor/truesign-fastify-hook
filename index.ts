import * as crypto from 'crypto';

export interface DecryptedToken {
  // network
  proxy: boolean;
  vpn: boolean;
  tor: boolean;

  // email
  email: string;
  disposable: boolean;
  noMx: boolean;
  fake: boolean;
  typo: string;

  // agent
  script: boolean;

  // high load attacks
  clusterId: string;

  // identifiers
  uniqueKey: number;
  timestamp: number;
  visitorId: string;
  ipv4: string;
  ipv6: string;
  country: string;

  // the reason why Truesign decides to block a visitor
  block: 'gproxy' | 'vpn' | 'tor' | 'disposable' | 'notdeliverable' | 'script' | 'cluster' | 'country' | 'ratelimit';

  // something went wrong on our side
  error: {
    correlationId: number;
    ip: string;
    email: string;
  };
}
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
  config?: Omit<TruesignHookConfig, 'shouldAcceptToken'>,
  ) => boolean;

export interface TruesignHookConfig {
  encryptionKey: string;
  allowUnauthenticated: boolean;
  shouldAcceptToken: ShouldAcceptTokenFunction;
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
  if (config.allowUnauthenticated || !config.encryptionKey) {
    return next();
  }
  const tsToken = req.query[config.queryStringPath || 'tsToken'];
  if (!tsToken) {
    return res.code(401).send();
  }
  const decryptedToken = (config.decryptFunction || decryptTruesignToken)(config.encryptionKey, tsToken);
  if (!config.shouldAcceptToken(decryptedToken, config)) {
    return res.code(401).send();
  }
  req[config.queryStringPath || 'tsToken'] = decryptedToken;
  next();
};