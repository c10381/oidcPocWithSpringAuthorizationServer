package com.dennis.auth.keycloak.config;

import java.util.HashMap;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "keycloak")
public class KeycloakProperties extends HashMap<String, Object> {
}
