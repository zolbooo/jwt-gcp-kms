import { KeyManagementServiceClient } from '@google-cloud/kms';

import { getPublicKeys } from '../src/public-keys';

const client = new KeyManagementServiceClient({ projectId: 'jwt-gcp-kms' });
async function destroyActiveKeyVersions(keyPath: string) {
  const [result] = await client.listCryptoKeyVersions({
    parent: keyPath,
    filter: 'state=ENABLED',
  });
  if (result.length > 0) {
    await Promise.all(
      result.map((cryptoKeyVersion) =>
        client.destroyCryptoKeyVersion({
          name: cryptoKeyVersion.name,
        }),
      ),
    );
  }
}

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
