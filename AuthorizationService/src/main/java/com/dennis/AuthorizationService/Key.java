//package com.dennis.AuthorizationService;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.security.core.context.SecurityContext;
//
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.NoSuchAlgorithmException;
//import java.security.interfaces.RSAKey;
//import java.security.interfaces.RSAPrivateKey;
//import java.security.interfaces.RSAPublicKey;
//
//public class Key {
//
////    @Bean
////    public JWKSource<SecurityContext> jwkSource() {
////        RSAKey rsaKey = generateRsa();
////        JWKSet jwkSet = new JWKSet(rsaKey);
////        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
////    }
//
//    private static RSAKey generateRsa() throws NoSuchAlgorithmException {
//        KeyPair keyPair = generateRsaKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//        return new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//    }
//
//    private static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(2048);
//        return keyPairGenerator.generateKeyPair();
//    }
//}
