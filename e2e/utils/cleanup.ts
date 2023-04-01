import { KeyManagementServiceClient } from '@google-cloud/kms';

export async function destroyActiveKeyVersions(
  client: KeyManagementServiceClient,
  keyPath: string,
) {
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
