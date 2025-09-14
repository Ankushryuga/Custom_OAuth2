package com.example.authserver.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

@RestController
@RequestMapping("/connect")
public class DcrController {
  private final RegisteredClientRepository repo;
  private final PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
  public DcrController(RegisteredClientRepository repo) { this.repo = repo; }

  @Value("${auth.dcr.require-initial-token:true}") private boolean requireInitialToken;
  @Value("${auth.dcr.initial-token:dev-dcr-token-123}") private String initialToken;

  public static final class DcrRequest {
    public String client_name;
    public String client_type; // public|confidential
    public List<String> redirect_uris;
    public List<String> post_logout_redirect_uris;
    public String scope;
    public String token_endpoint_auth_method;
  }
  public static final class DcrResponse {
    public String client_id, client_secret, token_endpoint_auth_method;
    public List<String> redirect_uris, post_logout_redirect_uris;
    public DcrResponse(String id, String sec, List<String> r, List<String> pr, String m) {
      client_id=id; client_secret=sec; redirect_uris=r; post_logout_redirect_uris=pr; token_endpoint_auth_method=m;
    }
  }

  @PostMapping("/register")
  public ResponseEntity<?> register(@RequestHeader Map<String,String> headers, @RequestBody DcrRequest req) {
    if (requireInitialToken) {
      String authz = headers.getOrDefault("authorization","");
      if (!authz.startsWith("Bearer ")) return ResponseEntity.status(401).body(Map.of("error","missing bearer"));
      if (!Objects.equals(authz.substring(7), initialToken)) return ResponseEntity.status(403).body(Map.of("error","bad token"));
    }

    boolean isPublic = "public".equalsIgnoreCase(req.client_type);
    String clientId = UUID.randomUUID().toString();
    String clientSecret = isPublic ? null : UUID.randomUUID().toString();

    RegisteredClient.Builder b = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientIdIssuedAt(Instant.now())
            .clientName(Optional.ofNullable(req.client_name).orElse("Unnamed"))
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(30)).reuseRefreshTokens(false).build());

    if (req.scope != null) for (String s : req.scope.split("\\s+")) if (!s.isBlank()) b.scope(s.trim());
    if (req.redirect_uris != null) for (String u : req.redirect_uris) if (u!=null && !u.isBlank()) b.redirectUri(u.trim());
    if (req.post_logout_redirect_uris != null) for (String u : req.post_logout_redirect_uris) if (u!=null && !u.isBlank()) b.postLogoutRedirectUri(u.trim());

    if (isPublic) {
      b.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
              .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build());
    } else {
      String method = Optional.ofNullable(req.token_endpoint_auth_method).orElse("client_secret_basic");
      if ("client_secret_post".equalsIgnoreCase(method)) b.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
      else if ("private_key_jwt".equalsIgnoreCase(method)) b.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
      else b.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
      b.clientSecret(encoder.encode(Objects.requireNonNullElse(clientSecret,"")));
    }

    repo.save(b.build());
    return ResponseEntity.created(URI.create("/connect/register/"+clientId))
            .body(new DcrResponse(clientId, clientSecret, req.redirect_uris, req.post_logout_redirect_uris,
                    isPublic ? "none" : Optional.ofNullable(req.token_endpoint_auth_method).orElse("client_secret_basic")));
  }
}
