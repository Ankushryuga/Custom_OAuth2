package com.customoauth2.customAuth20.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class ResourceController {
    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt){
        return Map.of(
                "userId", jwt.getSubject(),
                "email", jwt.getClaimAsString("email"),
                "scope", jwt.getClaimAsString("scope"),
                "roles", jwt.getClaimAsStringList("roles")      // if available
        );
    }

    @GetMapping("/greeting")
    public String greeting(@AuthenticationPrincipal Jwt jwt){
        return "Hello " + jwt.getSubject() + " 👋";
    }
}
