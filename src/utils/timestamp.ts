import type { google } from '@google-cloud/kms/build/protos/protos';

export function timestampToDate(
  timestamp?: google.protobuf.ITimestamp | null,
): Date {
  if (!timestamp) {
    return new Date(0);
  }
  return new Date(
    typeof timestamp.seconds === 'object'
      ? (timestamp.seconds?.toNumber() ?? 0) * 1000
      : Number(timestamp.seconds ?? 0) + Number(timestamp.nanos ?? 0) / 1000000,
  );
}
