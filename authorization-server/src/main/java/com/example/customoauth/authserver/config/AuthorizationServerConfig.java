//package com.example.customoauth.authserver.config;
//
//import com.nimbusds.jose.jwk.JWKSet;
//import com.nimbusds.jose.jwk.RSAKey;
//import com.nimbusds.jose.jwk.source.JWKSource;
//import com.nimbusds.jose.proc.SecurityContext;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.jdbc.core.JdbcOperations;
//import org.springframework.jdbc.core.JdbcTemplate;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.oauth2.jwt.JwtDecoder;
//import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
//import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
//import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
//import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
//import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//import org.springframework.security.web.SecurityFilterChain;
//
//import javax.sql.DataSource;
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.interfaces.RSAPrivateKey;
//import java.security.interfaces.RSAPublicKey;
//import java.util.UUID;
//
//@Configuration
//public class AuthorizationServerConfig {
//
//  @Value("${spring.security.oauth2.authorizationserver.issuer:http://auth-server:9000}")
//  private String issuer;
//
//  @Bean
//  SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {
//    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//    http.getConfigurer(org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.class)
//            .oidc(Customizer.withDefaults());
//    return http.build();
//  }
//
//  // Provide JdbcOperations from your DataSource
//  @Bean
//  JdbcOperations jdbcOperations(DataSource dataSource) {
//    return new JdbcTemplate(dataSource);
//  }
//
//  @Bean
//  RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOps) {
//    return new JdbcRegisteredClientRepository(jdbcOps);
//  }
//
//  @Bean
//  OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOps, RegisteredClientRepository repo) {
//    return new JdbcOAuth2AuthorizationService(jdbcOps, repo);
//  }
//
//  @Bean
//  OAuth2AuthorizationConsentService authorizationConsentService(JdbcOperations jdbcOps, RegisteredClientRepository repo) {
//    return new JdbcOAuth2AuthorizationConsentService(jdbcOps, repo);
//  }
//
//  @Bean
//  JWKSource<SecurityContext> jwkSource() throws Exception {
//    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
//    g.initialize(2048);
//    KeyPair kp = g.generateKeyPair();
//    RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
//    RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();
//    RSAKey rsa = new RSAKey.Builder(pub).privateKey(priv).keyID(UUID.randomUUID().toString()).build();
//    JWKSet set = new JWKSet(rsa);
//    return (sel, ctx) -> sel.select(set);
//  }
//
//  @Bean
//  JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//  }
//
//  @Bean
//  AuthorizationServerSettings authorizationServerSettings() {
//    return AuthorizationServerSettings.builder().issuer(issuer).build();
//  }
//}


package com.example.customoauth.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {

  @Value("${spring.security.oauth2.authorizationserver.issuer:http://localhost:9000}")
  private String issuer;

  @Bean
  SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {
    // SAS endpoints + OIDC
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    http.getConfigurer(
            org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.class
    ).oidc(Customizer.withDefaults());

    // Validate JWTs on /userinfo (and other resource endpoints on AS)
    http.oauth2ResourceServer(o -> o.jwt());

    return http.formLogin(Customizer.withDefaults()).build();
  }

  // JDBC wiring for SAS 1.3.x
  @Bean
  JdbcOperations jdbcOperations(DataSource dataSource) {
    return new JdbcTemplate(dataSource);
  }

  @Bean
  RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOps) {
    return new JdbcRegisteredClientRepository(jdbcOps);
  }

  @Bean
  OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOps, RegisteredClientRepository repo) {
    return new JdbcOAuth2AuthorizationService(jdbcOps, repo);
  }

  @Bean
  OAuth2AuthorizationConsentService authorizationConsentService(JdbcOperations jdbcOps, RegisteredClientRepository repo) {
    return new JdbcOAuth2AuthorizationConsentService(jdbcOps, repo);
  }

  // JWK/JWT
  @Bean
  JWKSource<SecurityContext> jwkSource() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(2048);
    KeyPair kp = g.generateKeyPair();
    RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
    RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();
    RSAKey rsa = new RSAKey.Builder(pub).privateKey(priv).keyID(UUID.randomUUID().toString()).build();
    JWKSet set = new JWKSet(rsa);
    return (selector, ctx) -> selector.select(set);
  }

  @Bean
  JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().issuer(issuer).build();
  }
}
