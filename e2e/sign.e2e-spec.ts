import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';

import { signJWT } from '../src/jwt';

import { client } from './utils/client';
import { destroyActiveKeyVersions } from './utils/cleanup';

describe('JWT signing', () => {
  const keyPath = client.cryptoKeyPath(
    'jwt-gcp-kms',
    'global',
    'test-keys',
    'sign-test',
  );

  let keyVersionName: string;
  beforeAll(async () => {
    const [result] = await client.listCryptoKeyVersions({
      parent: keyPath,
      filter: 'state=ENABLED',
    });
    if (result.length === 0) {
      const [creationResult] = await client.createCryptoKeyVersion({
        parent: keyPath,
      });
      keyVersionName = creationResult.name as string;
    } else {
      keyVersionName = result[0].name as string;
    }
  });
  afterAll(async () => {
    await destroyActiveKeyVersions(keyPath);
  });

  it('should create JWT with correct structure', async () => {
    const token = await signJWT(
      client,
      { keyName: 'sign-test', keyRing: 'test-keys', region: 'global' },
      { payload: { aud: 'test' } },
    );
    expect(() => jwt.decode(token)).not.toThrow();
  });

  it('should create valid JWT', async () => {
    const [getPublicKeyResult] = await client.getPublicKey({
      name: keyVersionName,
    });
    const publicKey = crypto.createPublicKey(getPublicKeyResult.pem as string);

    const token = await signJWT(
      client,
      { keyName: 'sign-test', keyRing: 'test-keys', region: 'global' },
      { payload: { aud: 'test' } },
    );
    expect(
      jwt.verify(token, publicKey, { algorithms: ['ES256'], audience: 'test' }),
    ).toMatchObject({ aud: 'test' });
  });
});
