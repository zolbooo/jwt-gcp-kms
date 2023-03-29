import jwt, { JwtPayload, VerifyOptions } from 'jsonwebtoken';
import crypto from 'node:crypto';

import type { JsonWebKeySet } from '../public-keys';

export function verifyJWT(
  token: string,
  jwks: JsonWebKeySet,
  options?: VerifyOptions,
): JwtPayload {
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
  return jwt.verify(token, publicKey, options) as JwtPayload;
}
