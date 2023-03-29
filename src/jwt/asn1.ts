export function extractSignatureValue(data: Uint8Array, size = 32): Uint8Array {
  if (data.length === size) {
    return data;
  }
  if (data.length > size) {
    const start = data.length - size;
    for (let i = 0; i < start; i++) {
      if (data[i] != 0x00) {
        throw Error(
          `Signature overflow: found byte ${data[start]} at position ${start}, integer length is ${data.length}, but it must be ${size}`,
        );
      }
    }
    return data.slice(start);
  }

  const result = Buffer.alloc(size, 0x00);
  let dataIndex = data.length - 1;
  let resultIndex = result.length - 1;
  while (dataIndex >= 0) {
    result[resultIndex] = data[dataIndex];
    dataIndex -= 1;
    resultIndex -= 1;
  }
  return result;
}

export function convertASN1Signature(data: Uint8Array) {
  if (data[0] !== 0x30 || data.length < 2) {
    throw new Error('Invalid signature, expected ASN.1 SEQUENCE');
  }

  const sequence = data.slice(2, 2 + data[1]);
  if (sequence[0] !== 0x02 || sequence.length < 2) {
    throw new Error(
      'Invalid signature, expected ASN.1 INTEGER within SEQUENCE',
    );
  }

  const r = sequence.slice(2, 2 + sequence[1]);
  const sPosition = 2 + sequence[1];
  if (sequence[sPosition] !== 0x02 || sequence.length < sPosition + 2) {
    throw new Error(
      'Invalid signature, expected two ASN.1 INTEGERs within SEQUENCE',
    );
  }
  const s = sequence.slice(
    sPosition + 2,
    sPosition + 2 + sequence[sPosition + 1],
  );

  return Buffer.concat([extractSignatureValue(r), extractSignatureValue(s)]);
}
