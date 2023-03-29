import crypto from 'node:crypto';
import { JwtHeader, JwtPayload } from 'jsonwebtoken';
import { KeyManagementServiceClient } from '@google-cloud/kms';

import { KeyPath } from './types';

import { signData } from './sign.js';
import { getLatestVersion } from './keys.js';
import { getPublicKey, getPublicKeyFingerprint } from './public-keys.js';

export async function signJWT(
  client: KeyManagementServiceClient,
  { keyName, keyRing, region = 'asia-east2' }: KeyPath,
  token: { header?: JwtHeader; payload: JwtPayload },
): Promise<string> {
  const keyLatestVersion = await getLatestVersion(
    client,
    client.cryptoKeyPath(await client.getProjectId(), region, keyRing, keyName),
  );
  const kid = getPublicKeyFingerprint(
    crypto.createPublicKey(await getPublicKey(client, keyLatestVersion.name)),
  );

  const header = { ...token.header, typ: 'JWT', alg: 'ES256', kid };
  const unprotectedToken = [
    Buffer.from(JSON.stringify(header)).toString('base64url'),
    Buffer.from(JSON.stringify(token.payload)).toString('base64url'),
  ].join('.');
  const signature = await signData(client, {
    keyVersionName: keyLatestVersion.name,
    algorithm: 'sha256',
    data: Buffer.from(unprotectedToken),
  });
  return [unprotectedToken, Buffer.from(signature).toString('base64url')].join(
    '.',
  );
}

export { verifyJWT } from './jwt/verify.js';
