/** @type {import('ts-jest/dist/types').InitialOptionsTsJest} */
export default {
  extensionsToTreatAsEsm: ['.ts'],
  preset: 'ts-jest',
  testRegex: '.e2e-spec.ts$',
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.ts$': ['ts-jest', { useESM: true }],
  },
};
