import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';

import { signJWT, verifyJWT } from '../src';
import { getLatestVersionName } from '../src/keys';
import { getPublicKeyFingerprint, getPublicKeys } from '../src/public-keys';

import { client } from './utils/client';
import { destroyActiveKeyVersions } from './utils/cleanup';

describe('Key rotation', () => {
  const keyPath = client.cryptoKeyPath(
    'jwt-gcp-kms',
    'global',
    'test-keys',
    'rotation-test',
  );

  let newVersionName: string;
  let oldVersionName: string;
  beforeAll(async () => {
    await destroyActiveKeyVersions(keyPath);

    const [oldKey] = await client.createCryptoKeyVersion({ parent: keyPath });
    oldVersionName = oldKey.name as string;
    // Add delay for new key version
    await new Promise((resolve) => setTimeout(resolve, 1000));
    const [newKey] = await client.createCryptoKeyVersion({ parent: keyPath });
    newVersionName = newKey.name as string;
  });
  afterAll(async () => {
    await destroyActiveKeyVersions(keyPath);
  });

  it('should get the latest version of key', async () => {
    const latestVersionName = await getLatestVersionName(client, keyPath);
    expect(latestVersionName).toBe(newVersionName);
  });

  it('should sign valid tokens with latest version', async () => {
    const [getPublicKeyResult] = await client.getPublicKey({
      name: newVersionName,
    });
    const publicKey = crypto.createPublicKey(getPublicKeyResult.pem as string);
    const kid = getPublicKeyFingerprint(publicKey);

    const token = await signJWT(
      client,
      {
        keyName: 'rotation-test',
        keyRing: 'test-keys',
        region: 'global',
      },
      { payload: { aud: 'test-rotation-new-version' } },
    );
    const decodedToken = jwt.decode(token, { complete: true });
    expect(decodedToken?.header.kid).toBe(kid);

    expect(
      jwt.verify(token, publicKey, {
        algorithms: ['ES256'],
        audience: 'test-rotation-new-version',
      }),
    );
  });

  it('should verify tokens signed with old key version', async () => {
    const [getPublicKeyResult] = await client.getPublicKey({
      name: oldVersionName,
    });
    const publicKey = crypto.createPublicKey(getPublicKeyResult.pem as string);
    const kid = getPublicKeyFingerprint(publicKey);

    const token = await signJWT(
      client,
      {
        keyName: 'rotation-test',
        keyRing: 'test-keys',
        region: 'global',
      },
      { payload: { aud: 'test-rotation-old-version' } },
      { keyVersion: oldVersionName },
    );
    const decodedToken = jwt.decode(token, { complete: true });
    expect(decodedToken?.header.kid).toBe(kid);

    const jwks = await getPublicKeys(client, {
      keyName: 'rotation-test',
      keyRing: 'test-keys',
      region: 'global',
    });
    expect(
      verifyJWT(token, jwks, {
        algorithms: ['ES256'],
        audience: 'test-rotation-old-version',
      }),
    ).toMatchObject({ aud: 'test-rotation-old-version' });
  });
});
