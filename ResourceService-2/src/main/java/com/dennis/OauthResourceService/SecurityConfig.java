package com.dennis.OauthResourceService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Autowired
  private ClientRegistrationRepository clientRegistrationRepository;

  @Bean
  SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
            .requestMatchers("/").permitAll()
              .anyRequest().authenticated())
            .sessionManagement(configuration ->
                    configuration.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
            .oauth2Login(oauth2Login -> {
              oauth2Login.authorizationEndpoint(endpoint ->
                      endpoint.authorizationRequestResolver(resolver()));
              oauth2Login.tokenEndpoint(tokenEndpointCustomizer ->
                      tokenEndpointCustomizer.accessTokenResponseClient(new DefaultAuthorizationCodeTokenResponseClient()));
            })
            .logout((logout) -> logout
                    .logoutSuccessHandler(oidcLogoutSuccessHandler())
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
            )
//            .oidcLogout(logout -> logout.backChannel(Customizer.withDefaults()))
            .oauth2ResourceServer(oauth2ResourceServer ->
                    oauth2ResourceServer.jwt(Customizer.withDefaults()))
            .oauth2Client(Customizer.withDefaults())
        .build();
  }

  /**
   * Logout Setting
   * @return
   */
  OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler() {
    OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
    successHandler.setPostLogoutRedirectUri("{baseUrl}/");
    return successHandler;
  }

  /**
   * PKCE Setting
   * @return
   */
  DefaultOAuth2AuthorizationRequestResolver resolver(){
    String auth_url = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
    DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, auth_url);
    resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
    return resolver;
  }
}