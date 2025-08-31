package com.example.authorizationserver.client;

import jakarta.annotation.PostConstruct;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.UUID;

@Component
public class DefaultClientLoader {

    private final RegisteredClientRepository repo;

    public DefaultClientLoader(RegisteredClientRepository repo) {
        this.repo = repo;
    }

    @PostConstruct
    public void init() {
        if (repo instanceof JdbcRegisteredClientRepository) {
            JdbcRegisteredClientRepository jdbc = (JdbcRegisteredClientRepository) repo;
            if (jdbc.findByClientId("client-app") == null) {
                RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("client-app")
                        .clientSecret("{noop}client-secret")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri("http://127.0.0.1:8082/login/oauth2/code/client-app")
                        .redirectUri("http://localhost:8082/login/oauth2/code/client-app")
                        .scope("openid").scope("profile").scope("email").scope("api.read")
                        .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(false)
                                .requireProofKey(false)
                                .build())
                        .tokenSettings(TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofMinutes(30))
                                .refreshTokenTimeToLive(Duration.ofDays(7))
                                .reuseRefreshTokens(false)
                                .build())
                        .build();
                jdbc.save(client);
            }
        }
    }
}
