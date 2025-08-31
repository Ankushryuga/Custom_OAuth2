// authorization-server/src/main/java/com/example/authorizationserver/client/ClientRegistrationService.java
package com.example.authorizationserver.client;

import com.example.authorizationserver.util.SecuredStringGenerator;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Service
public class ClientRegistrationService {

    private final RegisteredClientRepository repo;
    private final PasswordEncoder encoder;
    private final JdbcTemplate jdbc;

    public ClientRegistrationService(RegisteredClientRepository repo,
                                     ObjectProvider<PasswordEncoder> encoderProvider,JdbcTemplate jdbc) {
        this.repo = repo;
        // Use app bean if present; otherwise create a delegating encoder
        this.encoder = Optional.ofNullable(encoderProvider.getIfAvailable())
                .orElseGet(PasswordEncoderFactories::createDelegatingPasswordEncoder);
        this.jdbc = jdbc;

    }

    public CreatedClient createConfidential(String clientId,
                                            String clientName,
                                            Collection<String> redirectUris,
                                            Collection<String> scopes,
                                            boolean enableRefreshToken) {
        String rawSecret = SecuredStringGenerator.generateSecret();

        RegisteredClient.Builder b = base(clientId, clientName, redirectUris, scopes)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSecret(encoder.encode(rawSecret))
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(false)
                        .build());

        if (enableRefreshToken) {
            b.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        }

        RegisteredClient rc = b.build();
        // propagate 409 properly if duplicate
        try { repo.save(rc); } catch (DataIntegrityViolationException e) {
            throw new DuplicateClientIdException(clientId, e);
        }

        return new CreatedClient(rc.getClientId(), rawSecret);
    }

    public CreatedClient createPublicPkce(String clientId,
                                          String clientName,
                                          Collection<String> redirectUris,
                                          Collection<String> scopes,
                                          boolean enableRefreshToken) {
        RegisteredClient.Builder b = base(clientId, clientName, redirectUris, scopes)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build());

        if (enableRefreshToken) {
            b.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        }

        RegisteredClient rc = b.build();
        try { repo.save(rc); } catch (DataIntegrityViolationException e) {
            throw new DuplicateClientIdException(clientId, e);
        }
        return new CreatedClient(rc.getClientId(), null);
    }

    private RegisteredClient.Builder base(String clientId,
                                          String clientName,
                                          Collection<String> redirectUris,
                                          Collection<String> scopes) {
        if (clientId == null || clientId.isBlank()) clientId = "client-" + SecuredStringGenerator.generateId();
        if (clientName == null || clientName.isBlank()) clientName = clientId;
        if (redirectUris == null || redirectUris.isEmpty()) {
            throw new IllegalArgumentException("redirect_uris must not be empty");
        }
        if (scopes == null || scopes.isEmpty()) scopes = List.of("openid");

        TokenSettings tokens = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(10))
                .refreshTokenTimeToLive(Duration.ofDays(30))
                .reuseRefreshTokens(true)
                .build();

        RegisteredClient.Builder b = RegisteredClient.withId(SecuredStringGenerator.generateId())
                .clientId(clientId)
                .clientIdIssuedAt(Instant.now())
                .clientName(clientName)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .tokenSettings(tokens);

        redirectUris.forEach(b::redirectUri);
        scopes.forEach(b::scope);
        return b;
    }

    public record CreatedClient(String clientId, String clientSecret) {}

    public static class DuplicateClientIdException extends RuntimeException {
        public final String clientId;
        public DuplicateClientIdException(String clientId, Throwable cause) {
            super("ClientId already exists: " + clientId, cause);
            this.clientId = clientId;
        }
    }


    /** ✅ Works without repo.findAll(): queries the SAS table directly */
    public List<ClientSummaryDto> listAll() {
        String sql = """
            SELECT client_id, client_name, client_authentication_methods
            FROM oauth2_registered_client
            ORDER BY client_id
        """;
        return jdbc.query(sql, (rs, i) -> {
            String methods = Optional.ofNullable(rs.getString("client_authentication_methods")).orElse("");
            boolean isPublic = methods.toLowerCase().contains("none"); // public client => auth method 'none'
            return new ClientSummaryDto(
                    rs.getString("client_id"),
                    rs.getString("client_name"),
                    isPublic
            );
        });
    }

}
