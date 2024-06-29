import { JsonWebKey } from 'node:crypto';

export interface KeyPath {
  projectId?: string;
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
