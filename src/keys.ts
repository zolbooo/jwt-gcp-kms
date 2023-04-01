import { KeyManagementServiceClient } from '@google-cloud/kms';

import type { google } from '@google-cloud/kms/build/protos/protos';

function timestampToDate(timestamp?: google.protobuf.ITimestamp | null): Date {
  if (!timestamp) {
    return new Date(0);
  }
  return new Date(
    typeof timestamp.seconds === 'object'
      ? (timestamp.seconds?.toNumber() ?? 0) * 1000
      : Number(timestamp.seconds ?? 0) + Number(timestamp.nanos ?? 0) / 1000000,
  );
}

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
      timestampToDate(latestVersion.createTime).valueOf() >
      timestampToDate(versions[i].createTime).valueOf()
    ) {
      latestVersion = versions[i];
    }
  }
  return { name: latestVersion.name as string };
}
