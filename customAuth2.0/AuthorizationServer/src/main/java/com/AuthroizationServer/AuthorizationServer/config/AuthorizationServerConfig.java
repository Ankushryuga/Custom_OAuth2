package com.AuthroizationServer.AuthorizationServer.config;


import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {
    private final String issuer;

    public AuthorizationServerConfig(@Value("${app.issuer}") String issuer){
        this.issuer=issuer;
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    SecurityFilterChain authServerChain(HttpSecurity http) throws Exception{
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());   //enable OIDC endpoints
        return http.formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(){
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    @Bean
    RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate){
        JdbcRegisteredClientRepository repo=new JdbcRegisteredClientRepository(jdbcTemplate);
        // register two example clients if they don't exist
        if(repo.findByClientId("client-app")==null){
            RegisteredClient clientApp=RegisteredClient.withId(UUID.randomUUID().toString()).clientId("client-app").clientSecret("{noop}client-secret").clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantTypes(grantTypes->{grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
            grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
            })
                    .redirectUri("http://localhost:3000/login/oauth2/code/client-app").scope(OidcScopes.OPENID)
                    .scope("profile").scope("orders.read").clientSettings(ClientSettings.builder().requireAuthorizationConsent(true)
                            .requireProofKey(true)//PKCE
                            .build())
                            .tokenSettings(TokenSettings.builder()
                                    .accessTokenTimeToLive(Duration.ofMinutes(10))
                                    .refreshTokenTimeToLive(Duration.ofDays(15))
                                    .reuseRefreshTokens(false)
                                    .build())
                    .build();
            repo.save(clientApp);
        }
        if(repo.findByClientId("rs-caller")==null){
            RegisteredClient svc=RegisteredClient.withId(UUID.randomUUID().toString()).clientId("rs-caller").clientSecret("{noop}supersecret").clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("orders-reads").tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5))
                    .build()).build();
            repo.save(svc);
        }
    return repo;
    }


    @Bean
    OAuth2AuthorizationService auth2AuthorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository clients){
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, clients);
    }

    @Bean
    OAuth2AuthorizationConsentService consentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository clients){
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, clients);
    }

    @Bean(name = "authServerJwtDecoder")
    @Primary
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        // provided by SAS via JWKSource bean (see JwkConfig)
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}
