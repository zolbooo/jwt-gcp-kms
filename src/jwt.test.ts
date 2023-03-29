import { verifyJWT } from './jwt';
import { JsonWebKeySet } from './public-keys';

/*
Private key used:
{
	kty: 'EC',
	x: 'fT6AM9MRfRmQWQOTJTzztnLN8onWCFPykNsTiCINAzg',
	y: 'AYMiKfBY8ps6R6QDyFACde3FOEeaoTV8ntI0vWZTWIk',
	crv: 'P-256',
	d: 'gslIO_cjiRwCVWCkYqrsc2rHFrB1vkzaCru7uCqFzyI'
}
*/
describe('JWT', () => {
  const jwks: JsonWebKeySet = {
    keys: [
      {
        crv: 'P-256',
        kid: 'cUaIMPvYTqvoX8CRMUibK-dsmA5YB9WynBbI3jG-ld4',
        kty: 'EC',
        x: 're7QZrfwGJR8y5CLVL_HJsxTq-yDDL9ffwE_DSKhBu0',
        y: 'Gugkh4UNPK9GZ5e8SED2ARmp9Ag4dM9ZfHkUg0SbKNY',
      },
      {
        kty: 'EC',
        x: 'fT6AM9MRfRmQWQOTJTzztnLN8onWCFPykNsTiCINAzg',
        y: 'AYMiKfBY8ps6R6QDyFACde3FOEeaoTV8ntI0vWZTWIk',
        crv: 'P-256',
        kid: 'x_z6WERYKgth93sXpeldBDtGZQbiZfCd5gltPQp7irw',
      },
    ],
  };
  it('should verify ES256 tokens with JWK', () => {
    expect(
      verifyJWT(
        'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InhfejZXRVJZS2d0aDkzc1hwZWxkQkR0R1pRYmlaZkNkNWdsdFBRcDdpcncifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.SK08LmiZ4VdwdZhpbH813qjeBHh0rALEXk_cgpcP4KksBps_rkxu9Pdn7mYPq63vNlPQ6qiJPamuqkCMY9Mggg',
        jwks,
        { algorithms: ['ES256'] },
      ),
    ).toStrictEqual({
      admin: true,
      iat: 1516239022,
      name: 'John Doe',
      sub: '1234567890',
    });
  });
});
