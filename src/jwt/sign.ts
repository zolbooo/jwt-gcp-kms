import crypto from 'node:crypto';
import { crc32c } from '@aws-crypto/crc32c';
import { KeyManagementServiceClient } from '@google-cloud/kms';

import { convertASN1Signature } from './asn1.js';

export async function signData(
  client: KeyManagementServiceClient,
  {
    keyVersionName,
    algorithm,
    data,
  }: {
    keyVersionName: string;
    algorithm: 'sha256';
    data: Uint8Array;
  },
): Promise<Uint8Array> {
  const digest = crypto.createHash(algorithm).update(data).end().digest();
  const digestChecksum = crc32c(digest);
  const [signResponse] = await client.asymmetricSign({
    name: keyVersionName,
    digest: { sha256: digest },
    digestCrc32c: { value: digestChecksum },
  });
  // Optional, but recommended: perform integrity verification on signResponse.
  // For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
  // https://cloud.google.com/kms/docs/data-integrity-guidelines
  if (signResponse.name !== keyVersionName) {
    throw new Error('kmsSign: request corrupted in-transit');
  }
  if (!signResponse.verifiedDigestCrc32c) {
    throw new Error('kmsSign: request corrupted in-transit');
  }

  const asn1Signature = signResponse.signature as Uint8Array;
  if (crc32c(asn1Signature) !== Number(signResponse.signatureCrc32c!.value)) {
    throw new Error('kmsSign: response corrupted in-transit');
  }
  return convertASN1Signature(asn1Signature);
}
