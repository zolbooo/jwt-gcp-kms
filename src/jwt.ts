import ms from 'ms';
import crypto from 'node:crypto';
import { JwtHeader, JwtPayload, SignOptions } from 'jsonwebtoken';
import { KeyManagementServiceClient } from '@google-cloud/kms';

import type { KeyPath } from './types';

import { signData } from './jwt/sign.js';
import { getLatestVersionName } from './keys.js';
import { getPublicKey, getPublicKeyFingerprint } from './public-keys.js';

/**
 * Sign a JWT using the latest active version of crypto key.
 * @param keyPath The path of key
 * @param token Token data
 * @param options Some additional options provided by [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) library
 * @returns JWT string
 */
export async function signJWT(
  client: KeyManagementServiceClient,
  { keyName, keyRing, region = 'asia-east2' }: KeyPath,
  token: {
    header?: JwtHeader;
    payload: JwtPayload;
  },
  options?: Pick<SignOptions, 'expiresIn' | 'noTimestamp'> & {
    /**
     * Use this option to force signing a token with specific version of crypto key.
     */
    keyVersion?: string;
  },
): Promise<string> {
  const keyVersionName =
    options?.keyVersion ??
    (await getLatestVersionName(
      client,
      client.cryptoKeyPath(
        await client.getProjectId(),
        region,
        keyRing,
        keyName,
      ),
    ));
  if (!keyVersionName) {
    throw new Error('Key has no active versions');
  }
  const kid = getPublicKeyFingerprint(
    crypto.createPublicKey(await getPublicKey(client, keyVersionName)),
  );

  const header = { ...token.header, typ: 'JWT', alg: 'ES256', kid };
  const payload = { ...token.payload };
  const iat = Math.floor(Date.now() / 1000);
  if (!options?.noTimestamp) {
    payload.iat = iat;
  }
  if (options?.expiresIn) {
    payload.exp =
      typeof options.expiresIn === 'number'
        ? options.expiresIn
        : iat + Math.floor(ms(options.expiresIn) / 1000);
  }

  const unprotectedToken = [
    Buffer.from(JSON.stringify(header)).toString('base64url'),
    Buffer.from(JSON.stringify(payload)).toString('base64url'),
  ].join('.');
  const signature = await signData(client, {
    keyVersionName,
    algorithm: 'sha256',
    data: Buffer.from(unprotectedToken),
  });
  return [unprotectedToken, Buffer.from(signature).toString('base64url')].join(
    '.',
  );
}

export { verifyJWT } from './jwt/verify.js';
