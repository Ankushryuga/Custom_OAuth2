package com.AuthroizationServer.AuthorizationServer.config;

import com.AuthroizationServer.AuthorizationServer.model.Client;
import com.AuthroizationServer.AuthorizationServer.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class ClientConfig {

    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    // ✅ Explicit constructor injection (instead of relying only on Lombok)
    public ClientConfig(ClientRepository clientRepository, PasswordEncoder passwordEncoder) {
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        List<RegisteredClient> registeredClients = clientRepository.findAll().stream()
                .map(client -> RegisteredClient.withId(client.getId().toString())
                        .clientId(client.getClientId())
                        .clientSecret(passwordEncoder.encode(client.getClientSecret()))
                        .redirectUri(client.getRedirectUri())
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .scope(OidcScopes.OPENID)
                        .scope("profile")
                        .build()
                )
                .toList();

        return new InMemoryRegisteredClientRepository(registeredClients);
    }
}
