import { convertASN1Signature, extractSignatureValue } from './asn1';

describe('ASN.1 signature decoding', () => {
  describe('extractSignatureValue', () => {
    it('should zero-fill data in beginning', () => {
      expect(
        extractSignatureValue(
          Buffer.alloc(4).map((_, i) => i + 1),
          8,
        ),
      ).toStrictEqual(
        Buffer.from([0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]),
      );
    });

    it('should return 32 bytes of data', () => {
      expect(
        Buffer.from(
          extractSignatureValue(
            Buffer.alloc(64).map((_, i) => (i < 32 ? 0 : i)),
          ),
        ).toString('hex'),
      ).toBe(
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
      );
    });

    it('should take last n bytes of data', () => {
      expect(
        extractSignatureValue(
          Buffer.alloc(8).map((_, i) => (i < 4 ? 0 : i)),
          4,
        ),
      ).toStrictEqual(Buffer.from([0x04, 0x05, 0x06, 0x07]));
    });

    it('should throw error on overflow', () => {
      expect(() =>
        extractSignatureValue(Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05]), 4),
      ).toThrow();
    });

    it('should not throw error if number is not overflowing', () => {
      expect(
        extractSignatureValue(Buffer.from([0x00, 0x02, 0x03, 0x04, 0x05]), 4),
      ).toStrictEqual(Buffer.from([0x02, 0x03, 0x04, 0x05]));
    });
  });

  // See: https://asn1.io/asn1playground
  it('should convert ASN.1 sequence to JWT signature', () => {
    expect(
      convertASN1Signature(
        Buffer.from(
          '30440220012be13f70f82f6935d1025daa0a8e237b30abff2ea865cfc0f488088831ab7702201de5571337634f3336cd644ccb639ddf49fc470059bed59c6eed146fd4d2b254',
          'hex',
        ),
      ),
    ).toStrictEqual(
      Buffer.from(
        '012BE13F70F82F6935D1025DAA0A8E237B30ABFF2EA865CFC0F488088831AB771DE5571337634F3336CD644CCB639DDF49FC470059BED59C6EED146FD4D2B254',
        'hex',
      ),
    );
  });
});
