package com.dennis.auth.config.authentication.publicClientRefreshToken;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.StringUtils;

import java.util.Map;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.ERROR_URI;

public class PublicClientRefreshTokenAuthenticationProvider implements AuthenticationProvider {

    private static final OAuth2TokenType REFRESH_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.REFRESH_TOKEN);

    private final Log logger = LogFactory.getLog(getClass());

    private final RegisteredClientRepository registeredClientRepository;

    private final OAuth2AuthorizationService oAuth2Service;


    public PublicClientRefreshTokenAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
                                                          OAuth2AuthorizationService oAuth2Service)
    {
        this.registeredClientRepository = registeredClientRepository;
        this.oAuth2Service = oAuth2Service;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException
    {
        OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;

        if (!isSupportedClientAuthenticationMethod(clientAuthentication)) {
            return null;
        }

        String clientId = clientAuthentication.getPrincipal().toString();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throwInvalidParameter(OAuth2ParameterNames.CLIENT_ID, OAuth2ErrorCodes.INVALID_CLIENT, ERROR_URI);
        }

        this.logger.trace("Retrieved registered client");

        if (!registeredClient.getClientAuthenticationMethods().contains(clientAuthentication.getClientAuthenticationMethod())) {
            throwInvalidParameter("authentication_method", OAuth2ErrorCodes.INVALID_CLIENT, ERROR_URI);
        }

        this.logger.trace("Validated client authentication parameters");

        // Validate the "code_verifier" parameter for the public client
        authenticateParameters(clientAuthentication, registeredClient);

        this.logger.trace("Authenticated public client");

        return new OAuth2ClientAuthenticationToken(registeredClient,
                clientAuthentication.getClientAuthenticationMethod(), null);
    }

    @Override
    public boolean supports(Class<?> authentication)
    {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private boolean isSupportedClientAuthenticationMethod(OAuth2ClientAuthenticationToken clientAuthentication)
    {
        return ClientAuthenticationMethod.NONE.equals(clientAuthentication.getClientAuthenticationMethod());
    }

    private void authenticateParameters(OAuth2ClientAuthenticationToken clientAuthentication,
                                        RegisteredClient registeredClient)
    {
        Map<String, Object> parameters = clientAuthentication.getAdditionalParameters();
        if (!isSupportedAuthorizationGrantType(parameters)) {
            throwInvalidParameter(OAuth2ParameterNames.GRANT_TYPE, OAuth2ErrorCodes.INVALID_GRANT, null);
        }

        OAuth2Authorization authorization = this.oAuth2Service.findByToken((String) parameters.get(OAuth2ParameterNames.REFRESH_TOKEN),
                REFRESH_TOKEN_TYPE);
        if (authorization == null) {
            throwInvalidParameter(OAuth2ParameterNames.REFRESH_TOKEN, OAuth2ErrorCodes.INVALID_GRANT, null);
        }

        this.logger.trace("Retrieved authorization with refresh token");

        OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());

        String codeChallenge = (String) authorizationRequest.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE);
        if (!StringUtils.hasText(codeChallenge)) {
            if (registeredClient.getClientSettings().isRequireProofKey()) {
                this.logger.debug(LogMessage.format("Invalid request: code_challenge is required for registered client '%s'",
                        registeredClient.getId()));
                throwInvalidParameter(PkceParameterNames.CODE_CHALLENGE, OAuth2ErrorCodes.INVALID_GRANT, null);
            } else {
                this.logger.trace("Did not authenticate code verifier since requireProofKey=false");
            }
        }
    }

    private static boolean isSupportedAuthorizationGrantType(Map<String, Object> parameters) {
        return AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(parameters.get(OAuth2ParameterNames.GRANT_TYPE));
    }

    private static void throwInvalidParameter(String parameterName, String errorCode, String uri) {
        OAuth2Error error = new OAuth2Error(errorCode, "Client authentication failed: " + parameterName, uri);
        throw new OAuth2AuthenticationException(error);
    }
}