////package com.customoauth2.customAuth20.controller;
////
////import jakarta.servlet.http.HttpServletRequest;
////import jakarta.servlet.http.HttpServletResponse;
////import org.springframework.http.HttpStatus;
////import org.springframework.http.ResponseEntity;
////import org.springframework.security.core.Authentication;
////import org.springframework.security.core.annotation.AuthenticationPrincipal;
////import org.springframework.security.oauth2.core.oidc.user.OidcUser;
////import org.springframework.security.oauth2.core.user.OAuth2User;
////import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
////import org.springframework.web.bind.annotation.*;
////
////import java.util.HashMap;
////import java.util.Map;
////
////@RestController
////@RequestMapping("/api/auth")
////@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
////public class AuthController {
////
////    @GetMapping("/login")
////    public void login(HttpServletResponse response) {
////        // This will trigger OAuth2 login flow
////        response.setStatus(HttpServletResponse.SC_FOUND);
////        response.setHeader("Location", "/oauth2/authorization/client-app");
////    }
////
////    @GetMapping("/user")
////    public ResponseEntity<Map<String, Object>> getUser(
////            @AuthenticationPrincipal OAuth2User oauth2User,
////            @AuthenticationPrincipal OidcUser oidcUser,
////            Authentication authentication) {
////
////        if (authentication == null || !authentication.isAuthenticated()) {
////            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
////        }
////
////        Map<String, Object> userInfo = new HashMap<>();
////
////        if (oidcUser != null) {
////            userInfo.put("name", oidcUser.getFullName());
////            userInfo.put("email", oidcUser.getEmail());
////            userInfo.put("username", oidcUser.getPreferredUsername());
////            userInfo.put("sub", oidcUser.getSubject());
////            userInfo.put("claims", oidcUser.getClaims());
////            userInfo.put("authorities", oidcUser.getAuthorities());
////            userInfo.put("type", "OIDC");
////        } else if (oauth2User != null) {
////            userInfo.put("name", oauth2User.getName());
////            userInfo.put("attributes", oauth2User.getAttributes());
////            userInfo.put("authorities", oauth2User.getAuthorities());
////            userInfo.put("type", "OAuth2");
////        } else {
////            userInfo.put("name", authentication.getName());
////            userInfo.put("authorities", authentication.getAuthorities());
////            userInfo.put("type", "Basic");
////        }
////
////        return ResponseEntity.ok(userInfo);
////    }
////
////    @PostMapping("/logout")
////    public ResponseEntity<Map<String, String>> logout(
////            HttpServletRequest request,
////            HttpServletResponse response,
////            Authentication authentication) {
////
////        if (authentication != null) {
////            new SecurityContextLogoutHandler().logout(request, response, authentication);
////        }
////
////        Map<String, String> result = new HashMap<>();
////        result.put("message", "Logged out successfully");
////        return ResponseEntity.ok(result);
////    }
////
////    @GetMapping("/status")
////    public ResponseEntity<Map<String, Object>> getAuthStatus(Authentication authentication) {
////        Map<String, Object> status = new HashMap<>();
////        status.put("authenticated", authentication != null && authentication.isAuthenticated());
////        if (authentication != null) {
////            status.put("name", authentication.getName());
////            status.put("authorities", authentication.getAuthorities());
////        }
////        return ResponseEntity.ok(status);
////    }
////}
//
//package com.customoauth2.customAuth20.controller;
//
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.annotation.AuthenticationPrincipal;
//import org.springframework.security.oauth2.core.user.OAuth2User;
//import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.HashMap;
//import java.util.Map;
//
//@RestController
//@RequestMapping("/api/auth")
//@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
//public class AuthController {
//
//    @GetMapping("/login")
//    public void login(HttpServletResponse response) {
//        // Redirect to OAuth2 login
//        response.setStatus(HttpServletResponse.SC_FOUND);
//        response.setHeader("Location", "/oauth2/authorization/client-app");
//    }
//
//    @GetMapping("/user")
//    public ResponseEntity<Map<String, Object>> getUser(
//            @AuthenticationPrincipal OAuth2User oauth2User,
//            Authentication authentication) {
//
//        if (authentication == null || !authentication.isAuthenticated()) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
//        }
//
//        Map<String, Object> userInfo = new HashMap<>();
//        if (oauth2User != null) {
//            userInfo.put("name", oauth2User.getName());
//            userInfo.put("attributes", oauth2User.getAttributes());
//            userInfo.put("authorities", oauth2User.getAuthorities());
//        } else {
//            userInfo.put("name", authentication.getName());
//            userInfo.put("authorities", authentication.getAuthorities());
//        }
//
//        return ResponseEntity.ok(userInfo);
//    }
//
//    @PostMapping("/logout")
//    public ResponseEntity<Map<String, String>> logout(
//            HttpServletRequest request,
//            HttpServletResponse response,
//            Authentication authentication) {
//
//        if (authentication != null) {
//            new SecurityContextLogoutHandler().logout(request, response, authentication);
//        }
//
//        Map<String, String> result = new HashMap<>();
//        result.put("message", "Logged out successfully");
//        return ResponseEntity.ok(result);
//    }
//}

// Enhanced AuthController.java for Test OAuth2 App Backend
package com.customoauth2.customAuth20.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class AuthController {

    private final WebClient webClient;

    /**
     * Default OAuth2 client registration ID.  This value can be overridden via the
     * {@code oauth2.client-id} property in application.yml or as an environment variable
     * (e.g. OAUTH2_CLIENT_ID).  When no clientId is provided to the login endpoint, this
     * value will be used.
     */
    @Value("${oauth2.client-id:client-app}")
    private String defaultClientId;

    /**
     * Base URI of the authorization server (e.g. http://localhost:9000).  All token and
     * userinfo requests will be sent to this host rather than being hard‑coded.  Set
     * {@code oauth2.auth-server-base-uri} in your configuration to customise this.
     */
    @Value("${oauth2.auth-server-base-uri:http://localhost:9000}")
    private String authServerBaseUri;

    /**
     * URI for your front‑end application.  After completing a manual code exchange this
     * controller includes this URI in the response to instruct clients where to
     * navigate next.  Override via {@code frontend.redirect-uri} if your front end
     * runs on a different host or port.
     */
    @Value("${frontend.redirect-uri:http://localhost:3000}")
    private String frontendRedirectUri;

    @Autowired
    public AuthController(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
    }

    @GetMapping("/login")
    public void login(HttpServletResponse response,
                      @RequestParam(value = "clientId", required = false) String clientIdParam) {
        /*
         * Initiates the OAuth2 login flow.  You can override which client registration is used
         * by supplying a `clientId` query parameter (defaults to `client-app`).  The redirect URI
         * is not overridden here; it must match one of the values registered in the Authorization Server.
         */
        String clientIdToUse = (clientIdParam != null && !clientIdParam.isBlank()) ? clientIdParam : defaultClientId;
        String location = "/oauth2/authorization/" + clientIdToUse;
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", location);
    }

    @PostMapping("/token")
    public Mono<ResponseEntity<Map<String, Object>>> exchangeCodeForToken(@RequestBody Map<String, String> request) {
        String code = request.get("code");
        String redirectUri = request.get("redirect_uri");

        if (code == null || redirectUri == null) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Missing code or redirect_uri");
            return Mono.just(ResponseEntity.badRequest().body(error));
        }

        // Exchange authorization code for access token
        String tokenUri = authServerBaseUri + "/oauth2/token";
        return webClient
                .post()
                .uri(tokenUri)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + java.util.Base64.getEncoder().encodeToString((defaultClientId + ":client-secret").getBytes()))
                .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                        .with("code", code)
                        .with("redirect_uri", redirectUri))
                .retrieve()
                .bodyToMono(new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {})
                .map(tokenResponse -> {
                    // include a redirect hint back to the front‑end so callers know where to go next
                    tokenResponse.put("redirect", frontendRedirectUri);
                    return ResponseEntity.ok(tokenResponse);
                })
                .onErrorResume(error -> {
                    Map<String, Object> errorResponse = new HashMap<>();
                    errorResponse.put("error", "Token exchange failed");
                    errorResponse.put("message", error.getMessage());
                    return Mono.just(ResponseEntity.<Map<String, Object>>badRequest().body(errorResponse));
                });
    }

    @GetMapping("/user")
    public ResponseEntity<Map<String, Object>> getUser(
            @AuthenticationPrincipal OAuth2User oauth2User,
            @RegisteredOAuth2AuthorizedClient("client-app") OAuth2AuthorizedClient authorizedClient,
            Authentication authentication) {

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Map<String, Object> userInfo = new HashMap<>();

        if (oauth2User != null) {
            userInfo.put("name", oauth2User.getName());
            userInfo.put("attributes", oauth2User.getAttributes());
            userInfo.put("authorities", oauth2User.getAuthorities());
            userInfo.put("authenticated", true);

            // Add token information if available
            if (authorizedClient != null) {
                userInfo.put("tokenType", authorizedClient.getAccessToken().getTokenType().getValue());
                userInfo.put("scopes", authorizedClient.getAccessToken().getScopes());
                userInfo.put("expiresAt", authorizedClient.getAccessToken().getExpiresAt());
            }
        } else {
            userInfo.put("name", authentication.getName());
            userInfo.put("authorities", authentication.getAuthorities());
            userInfo.put("authenticated", true);
        }

        return ResponseEntity.ok(userInfo);
    }

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getAuthStatus(Authentication authentication) {
        Map<String, Object> status = new HashMap<>();
        status.put("authenticated", authentication != null && authentication.isAuthenticated());

        if (authentication != null && authentication.isAuthenticated()) {
            status.put("name", authentication.getName());
            status.put("authorities", authentication.getAuthorities());
            status.put("principal", authentication.getPrincipal().getClass().getSimpleName());
        }

        return ResponseEntity.ok(status);
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {

        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        Map<String, String> result = new HashMap<>();
        result.put("message", "Logged out successfully");
        result.put("redirect", "http://localhost:3000");
        return ResponseEntity.ok(result);
    }

    // New endpoint to get user info using access token
    @GetMapping("/userinfo")
    public Mono<ResponseEntity<Object>> getUserInfo(
            @RegisteredOAuth2AuthorizedClient("client-app") OAuth2AuthorizedClient authorizedClient) {

        if (authorizedClient == null) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "No authorized client found");
            return Mono.just(ResponseEntity.badRequest().body(error));
        }

        String userInfoUri = authServerBaseUri + "/userinfo";
        return webClient
                .get()
                .uri(userInfoUri)
                .headers(headers -> headers.setBearerAuth(authorizedClient.getAccessToken().getTokenValue()))
                .retrieve()
                .bodyToMono(Map.class)
                .map(userInfo -> ResponseEntity.ok((Object) userInfo))
                .onErrorResume(error -> {
                    Map<String, Object> errorResponse = new HashMap<>();
                    errorResponse.put("error", "Failed to get user info");
                    errorResponse.put("message", error.getMessage());
                    return Mono.just(ResponseEntity.badRequest().body(errorResponse));
                });
    }
}