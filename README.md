# jwt-gcp-kms

JWT library with GCP KMS support

## Features

- JWT signing and verification (based on [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) library)
- Exporting active key version to [JSON Web Key Set](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets)

## Examples

Usage scenarios are covered in end-to-end tests. You can see the list of use cases below.

### Scenarios

- [Signing](e2e/sign.e2e-spec.ts)
- [Key rotation](e2e/key-rotation.e2e-spec.ts)
- [Retrieving public keys](e2e/public-keys.e2e-spec.ts)
