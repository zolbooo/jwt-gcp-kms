import { google } from '@google-cloud/kms/build/protos/protos';

import { timestampToDate } from './timestamp';

describe('Timestamp conversion', () => {
  it('should convert timestamp to correct date', () => {
    expect(
      timestampToDate(
        google.protobuf.Timestamp.fromObject({
          seconds: '1680371315',
          nanos: 972022534,
        }),
      ).toISOString(),
    ).toBe('2023-04-01T17:48:35.000Z');

    expect(
      timestampToDate(
        google.protobuf.Timestamp.fromObject({
          seconds: 1680371315,
          nanos: 972022534,
        }),
      ).toISOString(),
    ).toBe('2023-04-01T17:48:35.000Z');
  });
});
