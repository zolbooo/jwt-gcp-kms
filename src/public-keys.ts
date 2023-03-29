import crypto, { KeyObject } from 'node:crypto';
import { crc32c } from '@aws-crypto/crc32c';
import { KeyManagementServiceClient } from '@google-cloud/kms';

import type { JsonWebKeySet, JsonWebKeyWithID, KeyPath } from './types';

export function getPublicKeyFingerprint(publicKey: KeyObject): string {
  // Algorithm was adapted from: https://github.com/phra/key-fingerprint/blob/master/index.ts
  return (
    crypto
      .createHash('sha256')
      // We use DER encoding, which is a binary format,
      // which is more efficient for hashing than PEM.
      // See:
      // https://en.wikipedia.org/wiki/X.690#DER_encoding
      // https://wikipedia.org/wiki/SPKI
      .update(publicKey.export({ format: 'der', type: 'spki' }))
      .end()
      .digest()
      .toString('base64url')
  );
}
export function convertPublicPemToJWK(pem: string): JsonWebKeyWithID {
  const publicKey = crypto.createPublicKey(pem);
  return {
    ...publicKey.export({ format: 'jwk' }),
    kid: getPublicKeyFingerprint(publicKey),
  };
}

export async function getPublicKey(
  client: KeyManagementServiceClient,
  keyVersionName: string,
): Promise<string> {
  const [key] = await client.getPublicKey({
    name: keyVersionName,
  });
  // See: https://cloud.google.com/kms/docs/samples/kms-get-public-key
  if (key.name !== keyVersionName) {
    throw new Error('getPublicKey: request corrupted in-transit');
  }
  if (crc32c(Buffer.from(key.pem as string)) !== Number(key.pemCrc32c?.value)) {
    throw Error('getPublicKey: public key was corrupted in-transit');
  }
  return key.pem as string;
}

/**
 * List public keys of specific key in KMS
 * @param keyName Name of the key
 * @returns List of active public keys in JWKS format
 */
export async function getPublicKeys(
  client: KeyManagementServiceClient,
  { keyRing, keyName, region = 'asia-east2' }: KeyPath,
): Promise<JsonWebKeySet> {
  const [versions] = await client.listCryptoKeyVersions({
    parent: client.cryptoKeyPath(
      await client.getProjectId(),
      region,
      keyRing,
      keyName,
    ),
    filter: 'state=ENABLED',
  });

  const keys = await Promise.all(
    versions.map((version) => getPublicKey(client, version.name as string)),
  );
  return { keys: keys.map((key) => convertPublicPemToJWK(key)) };
}
