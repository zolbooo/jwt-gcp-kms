import jwt, { Jwt, JwtPayload, VerifyOptions } from 'jsonwebtoken';
import crypto from 'node:crypto';

import type { JsonWebKeySet } from '../types';

/**
 * Verify JWT against specific key set.
 * @param token JWT to verify
 * @param jwks Public key set in JWKS format. Can be retrieved using `getPublicKeys` function.
 * @param options Some additional options provided by [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) library
 * @returns JWT payload, or complete token data/token itself if `complete` option was set.
 */
export function verifyJWT(
  token: string,
  jwks: JsonWebKeySet,
  options?: VerifyOptions,
): JwtPayload | Jwt | string {
  const rawTokenData = jwt.decode(token, { complete: true });
  if (!rawTokenData?.header.kid) {
    throw Error('No kid provided in token');
  }
  const { kid } = rawTokenData.header;

  const publicKeyJwk = jwks.keys.find((key) => key.kid === kid);
  if (!publicKeyJwk) {
    throw Error(`Key with id ${kid} was not found`);
  }

  const publicKey = crypto.createPublicKey({
    key: publicKeyJwk,
    format: 'jwk',
  });
  return jwt.verify(token, publicKey, options);
}
