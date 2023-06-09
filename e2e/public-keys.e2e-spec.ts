import { getPublicKeys } from '../src/public-keys';

import { client } from './utils/client';
import { destroyActiveKeyVersions } from './utils/cleanup';

describe('Public keys', () => {
  const keyPath = client.cryptoKeyPath(
    'jwt-gcp-kms',
    'global',
    'test-keys',
    'public-keys-test',
  );
  beforeAll(async () => {
    await destroyActiveKeyVersions(keyPath);
    // Create two new key versions
    await client.createCryptoKeyVersion({ parent: keyPath });
    await client.createCryptoKeyVersion({ parent: keyPath });
  });
  afterAll(async () => {
    await destroyActiveKeyVersions(keyPath);
  });

  it('should get public keys properly', async () => {
    const jwks = await getPublicKeys(client, {
      keyRing: 'test-keys',
      keyName: 'public-keys-test',
      region: 'global',
    });
    expect(jwks.keys).toHaveLength(2);
    expect(jwks.keys[0].kid !== jwks.keys[1].kid);
  });
});
