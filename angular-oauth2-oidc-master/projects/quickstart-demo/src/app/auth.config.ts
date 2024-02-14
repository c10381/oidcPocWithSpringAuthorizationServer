import { AuthConfig } from 'angular-oauth2-oidc';

export const authCodeFlowConfig: AuthConfig = {
  requireHttps: false,
  issuer: 'http://auth-server:8080',
  redirectUri: window.location.origin + '/index.html',
  clientId: 'angular-oidc',
  responseType: 'code',
  scope: 'openid profile email offline_access api',
  showDebugInformation: true,
  timeoutFactor: 0.01,
  checkOrigin: false,
};
