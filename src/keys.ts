import { KeyManagementServiceClient } from '@google-cloud/kms';

export async function getLatestVersionName(
  client: KeyManagementServiceClient,
  keyName: string,
): Promise<string | null> {
  const [versions] = await client.listCryptoKeyVersions({
    parent: keyName,
    filter: 'state=ENABLED',
    orderBy: 'name desc',
  });
  return versions[0]?.name ?? null;
}
