import { JsonWebKey } from 'node:crypto';

export interface KeyPath {
  keyName: string;
  keyRing: string;
  region: string;
}

export interface JsonWebKeyWithID extends JsonWebKey {
  kid: string;
}
export interface JsonWebKeySet {
  keys: JsonWebKeyWithID[];
}
