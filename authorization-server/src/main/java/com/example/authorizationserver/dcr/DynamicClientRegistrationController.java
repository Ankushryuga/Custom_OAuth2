// authorization-server/src/main/java/com/example/authorizationserver/dcr/DynamicClientRegistrationController.java
package com.example.authorizationserver.dcr;

import com.example.authorizationserver.client.ClientRegistrationService;
import com.example.authorizationserver.client.ClientRegistrationService.DuplicateClientIdException;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static com.example.authorizationserver.dcr.DcrDtos.*;

@RestController
@EnableConfigurationProperties(DcrProperties.class)
public class DynamicClientRegistrationController {

    private final ClientRegistrationService service;
    private final DcrProperties props;

    public DynamicClientRegistrationController(ClientRegistrationService service, DcrProperties props) {
        this.service = service;
        this.props = props;
    }

    @PostMapping(path = "/connect/register", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> register(@RequestHeader HttpHeaders headers,
                                      @RequestBody ClientRegistrationRequest req) {
        // --- dev initial access token check ---
        if (props.isRequireInitialToken()) {
            String token = headers.getFirst("X-Initial-Access");
            if (token != null && token.startsWith("Bearer ")) token = token.substring(7);
            if (token == null || !token.equals(props.getInitialToken())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                        Map.of("error","invalid_token","error_description","initial access token required")
                );
            }
        }

        // --- minimal validation ---
        if (req.redirect_uris == null || req.redirect_uris.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error","invalid_client_metadata","error_description","redirect_uris required"));
        }
        List<String> scopes = (req.scope == null || req.scope.isBlank())
                ? List.of("openid")
                : Arrays.asList(req.scope.trim().split("\\s+"));
        boolean wantsRefresh = req.grant_types != null && req.grant_types.stream()
                .anyMatch(gt -> "refresh_token".equalsIgnoreCase(gt));
        boolean publicClient = "none".equalsIgnoreCase(req.token_endpoint_auth_method);

        // Choose a unique client_id (don’t derive from name to avoid collisions)
        String clientId = null; // null means "auto-generate" inside service

        try {
            var created = publicClient
                    ? service.createPublicPkce(clientId, req.client_name, req.redirect_uris, scopes, wantsRefresh)
                    : service.createConfidential(clientId, req.client_name, req.redirect_uris, scopes, wantsRefresh);

            ClientRegistrationResponse resp = new ClientRegistrationResponse();
            resp.client_id = created.clientId();
            resp.client_secret = created.clientSecret();   // null for public client
            resp.client_id_issued_at = Instant.now().getEpochSecond();
            resp.client_secret_expires_at = 0;
            resp.redirect_uris = req.redirect_uris;
            resp.grant_types = req.grant_types;
            resp.response_types = req.response_types;
            resp.scope = String.join(" ", scopes);
            resp.token_endpoint_auth_method = publicClient ? "none" : "client_secret_basic";

            return ResponseEntity.status(HttpStatus.CREATED).body(resp);
        } catch (DuplicateClientIdException | DataIntegrityViolationException ex) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(
                    Map.of("error","invalid_client_metadata","error_description","client_id already exists")
            );
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(
                    Map.of("error","invalid_client_metadata","error_description", ex.getMessage())
            );
        }
    }
}
