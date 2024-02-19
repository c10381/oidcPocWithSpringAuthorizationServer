package com.dennis.config;

import java.time.Instant;
import java.util.*;

import com.dennis.authentication.refreshToken.PublicClientRefreshTokenAuthenticationConverter;
import com.dennis.authentication.refreshToken.PublicClientRefreshTokenAuthenticationProvider;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.function.Consumer;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
public class AuthorizationServerConfig {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(
			HttpSecurity http, RegisteredClientRepository registeredClientRepository,
			JWKSource<SecurityContext> jwkSource,
			JdbcOAuth2AuthorizationService authorizationService) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		http.cors(Customizer.withDefaults())
				.headers(c -> c.frameOptions(FrameOptionsConfig::disable))
				.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
				.tokenGenerator(refreshTokenGenerator(new NimbusJwtEncoder(jwkSource)))
				.authorizationEndpoint(authorizationEndpoint ->
						authorizationEndpoint.authenticationProviders(configureAuthenticationValidator()))
				.clientAuthentication(clientAuthentication ->
						clientAuthentication
								.authenticationConverter(new PublicClientRefreshTokenAuthenticationConverter())
								.authenticationProvider(new PublicClientRefreshTokenAuthenticationProvider(registeredClientRepository, authorizationService))
			)
			.oidc(Customizer.withDefaults());
		http
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			)
			.oauth2ResourceServer(oauth2ResourceServer ->
				oauth2ResourceServer.jwt(conf -> conf.decoder(OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource))));

		return http.build();
	}

	@Bean
	public JdbcRegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("messaging-client")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.postLogoutRedirectUri("http://127.0.0.1:8080/logged-out")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("message.read")
				.scope("message.write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();

		RegisteredClient registeredClient2 = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("angular-oidc")
//				.clientSecret("{noop}secret1")
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://oidc-ui:4200/*")
				.postLogoutRedirectUri("http://oidc-ui:4200/index.html")
				.scope(OidcScopes.OPENID)
				.scope("ui")
//				.scope("message.read")
//				.scope("message.write")
				.clientSettings(ClientSettings.builder()
						.requireAuthorizationConsent(false)
						.requireProofKey(true)
						.build())
				.build();

		RegisteredClient deviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("device-messaging-client")
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.scope("message.read")
				.scope("message.write")
				.build();

		// Save registered client's in db as if in-memory
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		registeredClientRepository.save(registeredClient);
		registeredClientRepository.save(registeredClient2);
		registeredClientRepository.save(deviceClient);

		return registeredClientRepository;
	}

	@Bean
	public JdbcOAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	public JdbcOAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		// Will be used by the ConsentController
		return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	/**
	 * 檢查redirect url相關設定
 	 */
	private Consumer<List<AuthenticationProvider>> configureAuthenticationValidator() {
		return (authenticationProviders) ->
				authenticationProviders.forEach((authenticationProvider) -> {
					if (authenticationProvider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider) {// Override default redirect_uri validator
						Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator =
								redirectUrlWildcardValidator
										.andThen(OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR); // Reuse default scope validator
						((OAuth2AuthorizationCodeRequestAuthenticationProvider) authenticationProvider).setAuthenticationValidator(authenticationValidator);
					}
				});
	}

	Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> redirectUrlWildcardValidator = (context) -> {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				context.getAuthentication();
		RegisteredClient registeredClient = context.getRegisteredClient();
		Set<String> clientAllowRedirectUris = registeredClient.getRedirectUris();
		String requestedRedirectUri = Optional.ofNullable(authorizationCodeRequestAuthentication.getRedirectUri())
				.orElseThrow(() -> new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), null));
		for(var clientAllowUris : clientAllowRedirectUris){
			if(match(clientAllowUris, requestedRedirectUri)){
				return;
			}
		}
		throw new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), null);
	};

	/**
	 * 檢查輸入的URL是否符合給定的模式。
	 * 如果模式中包含'*'，則'*'表示任意長度的任意字符。
	 * 對於其他特殊字符，如[], {}, (), ?, +, ^, $, |，進行轉義處理。
	 *
	 * @param pattern 網址模式，可能包含'*'作為通配符
	 * @param url 要檢查的URL字符串
	 * @return 如果URL符合模式，則返回true，否則返回false
	 */
	public static boolean match(String pattern, String url) {
		// 處理正則表達式的特殊字符
		String escapedPattern = pattern
				.replace(".", "\\.")
				.replace("*", ".*")
				.replace("?", "\\?")
				.replace("+", "\\+")
				.replace("^", "\\^")
				.replace("$", "\\$")
				.replace("|", "\\|")
				.replace("(", "\\(")
				.replace(")", "\\)")
				.replace("[", "\\[")
				.replace("]", "\\]")
				.replace("{", "\\{")
				.replace("}", "\\}");

		return url.matches(escapedPattern);
	}



	@Bean
	public EmbeddedDatabase embeddedDatabase() {
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.H2)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
	}

	/**
	 * Allow configurable refresh token strategy for PKCE authorization_code grant flow
	 * @param nimbusJwtEncoder
	 * @return
	 */
	OAuth2TokenGenerator<OAuth2Token> refreshTokenGenerator(NimbusJwtEncoder nimbusJwtEncoder) {
		JwtGenerator jwtGenerator = new JwtGenerator(nimbusJwtEncoder);
		OAuth2TokenGenerator<OAuth2RefreshToken> refreshTokenGenerator = context -> {
			final StringKeyGenerator tokenGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
			if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
				return null;
			}
			Instant issuedAt = Instant.now();
			Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
			return new OAuth2RefreshToken(tokenGenerator.generateKey(), issuedAt, expiresAt);
		};
		return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator);
	}
//
//	private static final class CustomRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {
//		private final StringKeyGenerator refreshTokenGenerator =
//				new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
//		@Override
//		public OAuth2RefreshToken generate(OAuth2TokenContext context) {
//			if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType()))
//			{
//				return null;
//			}
//			Instant issuedAt = Instant.now();
//			Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
//			return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt);
//		}
//	}
}