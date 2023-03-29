import { convertPublicPemToJWK } from "./public-keys";

describe("Public keys", () => {
  it("should convert PEM key to JWK properly", () => {
    expect(
      convertPublicPemToJWK(
        "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEre7QZrfwGJR8y5CLVL/HJsxTq+yD\nDL9ffwE/DSKhBu0a6CSHhQ08r0Znl7xIQPYBGan0CDh0z1l8eRSDRJso1g==\n-----END PUBLIC KEY-----\n"
      )
    ).toMatchInlineSnapshot(`
      {
        "crv": "P-256",
        "kid": "cUaIMPvYTqvoX8CRMUibK-dsmA5YB9WynBbI3jG-ld4",
        "kty": "EC",
        "x": "re7QZrfwGJR8y5CLVL_HJsxTq-yDDL9ffwE_DSKhBu0",
        "y": "Gugkh4UNPK9GZ5e8SED2ARmp9Ag4dM9ZfHkUg0SbKNY",
      }
    `);
  });
});
