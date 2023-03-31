import { KeyManagementServiceClient } from '@google-cloud/kms';

// TODO: Add e2e tests for this function
export async function getLatestVersion(
  client: KeyManagementServiceClient,
  keyName: string,
): Promise<{ name: string }> {
  const [versions] = await client.listCryptoKeyVersions({
    parent: keyName,
    filter: 'state=ENABLED',
  });
  let latestVersion = versions[0];
  for (let i = 1; i < versions.length; i += 1) {
    if (
      new Date(latestVersion.createTime as string).valueOf() >
      new Date(versions[i].createTime as string).valueOf()
    ) {
      latestVersion = versions[i];
    }
  }
  return { name: latestVersion.name as string };
}
