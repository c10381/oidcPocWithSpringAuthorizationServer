package com.dennis;

import com.dennis.auth.web.AuthorizationConsentController.ScopeWithDescription;
import java.sql.SQLException;
import java.util.Arrays;

import org.h2.tools.Server;
import org.springframework.context.annotation.Bean;
import org.thymeleaf.expression.Lists;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ImportRuntimeHints;

@SpringBootApplication
@ImportRuntimeHints(SpringAuthorizationServerApplication.DemoAuthorizationServerApplicationRuntimeHintsRegistrar.class)
public class SpringAuthorizationServerApplication {

	static class DemoAuthorizationServerApplicationRuntimeHintsRegistrar implements RuntimeHintsRegistrar {

		@Override
		public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
			// Thymeleaf
			hints.reflection().registerTypes(
					Arrays.asList(
							TypeReference.of(ScopeWithDescription.class),
							TypeReference.of(Lists.class)
					), builder ->
							builder.withMembers(MemberCategory.DECLARED_FIELDS,
									MemberCategory.INVOKE_DECLARED_CONSTRUCTORS, MemberCategory.INVOKE_DECLARED_METHODS)
			);
		}

	}

	@Bean(initMethod = "start", destroyMethod = "stop")
	public Server h2Server() throws SQLException {
		return Server.createTcpServer("-tcp", "-tcpAllowOthers", "-tcpPort", "9092");
	}

	public static void main(String[] args) {
		SpringApplication.run(SpringAuthorizationServerApplication.class, args);
	}

}
