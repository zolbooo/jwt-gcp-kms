import { convertASN1Signature } from './asn1';

describe('Sign data', () => {
  // See: https://asn1.io/asn1playground
  it('should convert ASN.1 sequence to JWT signature', () => {
    expect(
      convertASN1Signature(
        Buffer.from(
          '30440220012be13f70f82f6935d1025daa0a8e237b30abff2ea865cfc0f488088831ab7702201de5571337634f3336cd644ccb639ddf49fc470059bed59c6eed146fd4d2b254',
          'hex',
        ),
      ).equals(
        Buffer.from(
          '012BE13F70F82F6935D1025DAA0A8E237B30ABFF2EA865CFC0F488088831AB771DE5571337634F3336CD644CCB639DDF49FC470059BED59C6EED146FD4D2B254',
          'hex',
        ),
      ),
    ).toBe(true);
  });
});
