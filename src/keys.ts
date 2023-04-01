import { KeyManagementServiceClient } from '@google-cloud/kms';

import { timestampToDate } from './utils/timestamp';

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
      timestampToDate(latestVersion.createTime).valueOf() <
      timestampToDate(versions[i].createTime).valueOf()
    ) {
      latestVersion = versions[i];
    }
  }
  return { name: latestVersion.name as string };
}
