package com.AuthroizationServer.AuthorizationServer.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

@Configuration
public class JwkConfig {
    @Bean
    JWKSource<SecurityContext> jwkSource() throws Exception{
        RSAKey rsa= new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        JWKSet jwkSet=new JWKSet(rsa);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean(name = "resourceServerJwtDecoder")
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource){
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(){
        return context -> {
            if (context.getTokenType().getValue().equals("access_token")){
                context.getClaims().claim("aud", List.of("orders-api"));
            }
        };
    }

    @Bean
    TokenSettings tokenSettings(){
        return TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10)).refreshTokenTimeToLive(Duration.ofDays(15)).reuseRefreshTokens(false).build();
    }
}
