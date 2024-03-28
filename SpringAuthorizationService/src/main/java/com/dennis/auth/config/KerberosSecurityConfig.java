package com.dennis.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.kerberos.authentication.KerberosAuthenticationProvider;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosClient;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class KerberosSecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain kerberosSecurityFilterChain(HttpSecurity http) throws Exception {
        KerberosAuthenticationProvider kerberosAuthenticationProvider = kerberosAuthenticationProvider();
        KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider = kerberosServiceAuthenticationProvider();
        ProviderManager providerManager = new ProviderManager(kerberosAuthenticationProvider,
                kerberosServiceAuthenticationProvider);
        http.cors(Customizer.withDefaults())
                // removes windows pop up
//                .exceptionHandling(exceptionHandler -> exceptionHandler.authenticationEntryPoint(new SpnegoEntryPoint("/login")))
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/home").permitAll()
                        .requestMatchers("/assets/**", "/login","/logout", "/oauth/authorize", "/userinfo").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form.loginPage("/login").permitAll().defaultSuccessUrl("http://oidc-ui:4200/*"))
                .logout(LogoutConfigurer::permitAll)
                .authenticationProvider(kerberosAuthenticationProvider)
                .authenticationProvider(kerberosServiceAuthenticationProvider)
                .addFilterBefore(spnegoAuthenticationProcessingFilter(providerManager),
                        BasicAuthenticationFilter.class);
        return http.build();
    }

    public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(
            AuthenticationManager authenticationManager) {
        SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Bean
    public KerberosAuthenticationProvider kerberosAuthenticationProvider() {
        KerberosAuthenticationProvider provider = new KerberosAuthenticationProvider();
        SunJaasKerberosClient client = new SunJaasKerberosClient();
        client.setMultiTier(true);
        provider.setKerberosClient(client);
        provider.setUserDetailsService(dummyUserDetailsService());
        return provider;
    }

    @Bean
    public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() {
        KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
        provider.setTicketValidator(sunJaasKerberosTicketValidator());
        provider.setUserDetailsService(dummyUserDetailsService());
        return provider;
    }

    @Bean
    public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
        SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
        ticketValidator.setServicePrincipal("HTTP/oidc-ui@EXAMPLE.COM");
        FileSystemResource fs = new FileSystemResource("C:/Users/Dennis/IdeaProjects/oidcPocWithSpringAuthorizationServer/SpringAuthorizationService/src/main/resources/oidc.keytab");
        ticketValidator.setKeyTabLocation(fs);
        ticketValidator.setDebug(true);
        ticketValidator.setRefreshKrb5Config(true);
        // test if it reads the file
//        System.out.println(fs.exists());
        return ticketValidator;
    }

    @Bean
    public DummyUserDetailsService dummyUserDetailsService()
    {
        return new DummyUserDetailsService();
    }
}
