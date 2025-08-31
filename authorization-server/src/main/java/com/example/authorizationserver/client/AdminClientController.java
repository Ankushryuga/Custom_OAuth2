//package com.example.authorizationserver.client;
//
//import org.springframework.http.HttpStatus;
//import org.springframework.security.oauth2.core.AuthorizationGrantType;
//import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
//import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
//import org.springframework.web.bind.annotation.*;
//import org.springframework.web.server.ResponseStatusException;
//
//import java.time.Duration;
//import java.util.*;
//
//@RestController
//@RequestMapping("/admin/clients")
//public class AdminClientController {
//
//    private final RegisteredClientRepository repo;
//    public AdminClientController(RegisteredClientRepository repo) { this.repo = repo; }
//
//    @PostMapping
//    public Map<String, Object> register(@RequestBody NewClientRequest req) {
//        if (req.clientId() == null || req.clientId().isBlank()) {
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "clientId required");
//        }
//        if (!req.publicClient() && (req.clientSecret() == null || req.clientSecret().isBlank())) {
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "clientSecret required for confidential clients");
//        }
//
//        if (repo instanceof JdbcRegisteredClientRepository) {
//            JdbcRegisteredClientRepository jdbcRepo = (JdbcRegisteredClientRepository) repo;
//            if (jdbcRepo.findByClientId(req.clientId()) != null) {
//                throw new ResponseStatusException(HttpStatus.CONFLICT, "client_id already exists");
//            }
//        }
//
//        RegisteredClient.Builder b = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId(req.clientId())
//                .clientName(Optional.ofNullable(req.clientName()).orElse(req.clientId()));
//
//        if (req.publicClient()) {
//            b.clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE);
//        } else {
//            b.clientSecret("{noop}" + req.clientSecret());
//            b.clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
//        }
//
//        for (String gt : req.grantTypes()) {
//            b.authorizationGrantType(new AuthorizationGrantType(gt));
//        }
//        req.redirectUris().forEach(b::redirectUri);
//        req.scopes().forEach(b::scope);
//
//        b.clientSettings(ClientSettings.builder()
//                .requireProofKey(req.publicClient())
//                .requireAuthorizationConsent(false)
//                .build());
//
//        b.tokenSettings(TokenSettings.builder()
//                .accessTokenTimeToLive(Duration.ofMinutes(30))
//                .refreshTokenTimeToLive(Duration.ofDays(7))
//                .reuseRefreshTokens(false)
//                .build());
//
//        RegisteredClient rc = b.build();
//        repo.save(rc);
//
//        Map<String, Object> out = new LinkedHashMap<>();
//        out.put("client_id", rc.getClientId());
//        if (!req.publicClient()) out.put("client_secret", req.clientSecret());
//        out.put("redirect_uris", req.redirectUris());
//        out.put("grant_types", req.grantTypes());
//        out.put("scopes", req.scopes());
//        return out;
//    }
//
//    public record NewClientRequest(
//            String clientId,
//            String clientName,
//            List<String> redirectUris,
//            List<String> grantTypes,
//            List<String> scopes,
//            boolean publicClient,
//            String clientSecret
//    ) {}
//}

// authorization-server/src/main/java/com/example/authorizationserver/client/AdminClientController.java
package com.example.authorizationserver.client;

import com.example.authorizationserver.client.AdminDtos.CreateClientRequest;
import com.example.authorizationserver.client.AdminDtos.CreatedClientResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin/clients")
public class AdminClientController {

    private final ClientRegistrationService service;

    public AdminClientController(ClientRegistrationService service) {
        this.service = service;
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> create(@RequestBody CreateClientRequest req) {
        boolean wantsRefresh = req.grantTypes != null && req.grantTypes.stream()
                .anyMatch(gt -> "refresh_token".equalsIgnoreCase(gt));

        ClientRegistrationService.CreatedClient created =
                (req.publicClient != null && req.publicClient)
                        ? service.createPublicPkce(req.clientId, req.clientName, req.redirectUris, req.scopes, wantsRefresh)
                        : service.createConfidential(req.clientId, req.clientName, req.redirectUris, req.scopes, wantsRefresh);

        return ResponseEntity.ok(new CreatedClientResponse(
                created.clientId(),
                created.clientSecret(),     // shown once; store it now
                req.redirectUris, req.grantTypes, req.scopes
        ));
    }

    // ⬇️ Add this method here
    @GetMapping
    public List<ClientSummaryDto> list() {
        return service.listAll();
    }

}
