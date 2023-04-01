import { KeyManagementServiceClient } from '@google-cloud/kms';

export const client = new KeyManagementServiceClient({
  projectId: 'jwt-gcp-kms',
});
