package com.customoauth2.customAuth20.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
//import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/protected")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class ProtectedController {

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getMe(
            @AuthenticationPrincipal OAuth2User oauth2User,
            @AuthenticationPrincipal OidcUser oidcUser,
            Authentication authentication) {

        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("message", "This is protected data from Authorization Server");

        if (oidcUser != null) {
            userInfo.put("userDetails", Map.of(
                    "name", oidcUser.getFullName() != null ? oidcUser.getFullName() : "N/A",
                    "email", oidcUser.getEmail() != null ? oidcUser.getEmail() : "N/A",
                    "username", oidcUser.getPreferredUsername() != null ? oidcUser.getPreferredUsername() : "N/A",
                    "subject", oidcUser.getSubject(),
                    "authorities", oidcUser.getAuthorities()
            ));
        } else if (oauth2User != null) {
            userInfo.put("userDetails", Map.of(
                    "name", oauth2User.getName(),
                    "attributes", oauth2User.getAttributes(),
                    "authorities", oauth2User.getAuthorities()
            ));
        }

        userInfo.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(userInfo);
    }

    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getProfile(Authentication authentication) {
        Map<String, Object> profile = new HashMap<>();
        profile.put("message", "User profile from protected endpoint");
        profile.put("user", authentication.getName());
        profile.put("authorities", authentication.getAuthorities());
        profile.put("authenticated", authentication.isAuthenticated());

        return ResponseEntity.ok(profile);
    }
}

