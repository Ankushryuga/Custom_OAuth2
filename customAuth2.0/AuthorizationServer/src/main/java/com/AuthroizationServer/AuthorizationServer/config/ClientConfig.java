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
        // Build a RegisteredClient for each row in the clients table.  We parse the comma‑separated
        // redirect URIs, scopes and grant types to allow per‑client customisation.  If no scopes
        // are provided we fall back to "openid" and "profile".
        List<RegisteredClient> registeredClients = clientRepository.findAll().stream().map(client -> {
            RegisteredClient.Builder builder = RegisteredClient.withId(client.getId().toString())
                    .clientId(client.getClientId())
                    .clientSecret(passwordEncoder.encode(client.getClientSecret()));

            // Configure redirect URIs (may be comma‑separated in the DB)
            String redirectUriStr = client.getRedirectUri();
            if (redirectUriStr != null && !redirectUriStr.isBlank()) {
                for (String uri : redirectUriStr.split(",")) {
                    builder.redirectUri(uri.trim());
                }
            }

            // Configure supported authorization grant types
            String grantTypes = client.getGrantTypes();
            if (grantTypes != null && !grantTypes.isBlank()) {
                for (String grantType : grantTypes.split(",")) {
                    String trimmed = grantType.trim();
                    if (!trimmed.isEmpty()) {
                        builder.authorizationGrantType(new AuthorizationGrantType(trimmed));
                    }
                }
            } else {
                // Default grant types if none are specified
                builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                       .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                       .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
            }

            // Configure scopes
            String scopes = client.getScopes();
            if (scopes != null && !scopes.isBlank()) {
                for (String scope : scopes.split(",")) {
                    String trimmed = scope.trim();
                    if (!trimmed.isEmpty()) {
                        builder.scope(trimmed);
                    }
                }
            } else {
                // Always include the mandatory OpenID scope when no scopes are specified
                builder.scope(OidcScopes.OPENID).scope("profile");
            }

            return builder.build();
        }).toList();

        return new InMemoryRegisteredClientRepository(registeredClients);
    }
}
