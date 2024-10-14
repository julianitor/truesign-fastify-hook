import * as crypto from 'crypto';

export interface DynamicObject {
  [k: string]: any;
}

export interface DecryptedToken {
  anonymizer: boolean;
  notBrowser: boolean;
  clusterId: string;
  cors: string;

  // only added if an email or domain was passed on the request
  email: string;
  disposable: boolean;
  notDeliverable: boolean;
  typo: string;

  // identifiers
  uniqueKey: number;
  timestamp: number;
  ipv4: string;
  ipv6: string;
  country: string;
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
  options?: TruesignHookConfig,
  ) => boolean;

export interface TruesignHookConfig extends DynamicObject {
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
};