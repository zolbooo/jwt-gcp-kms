export function convertASN1Signature(data: Uint8Array) {
  if (
    !Buffer.from([0x30, 0x44, 0x02, 0x20]).equals(data.slice(0, 4)) ||
    !Buffer.from([0x02, 0x20]).equals(data.slice(4 + 32, 4 + 32 + 2))
  ) {
    throw new Error(
      'Invalid signature, expected ASN.1 SEQUENCE with 2 INTEGERS',
    );
  }
  return Buffer.concat([
    data.slice(4, 4 + 32),
    data.slice(4 + 32 + 2, 4 + 32 + 2 + 32),
  ]);
}
