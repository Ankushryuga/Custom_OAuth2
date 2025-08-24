//package com.customoauth2.customAuth20.controller;
//
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.annotation.AuthenticationPrincipal;
//import org.springframework.security.oauth2.core.oidc.user.OidcUser;
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
//        // This will trigger OAuth2 login flow
//        response.setStatus(HttpServletResponse.SC_FOUND);
//        response.setHeader("Location", "/oauth2/authorization/client-app");
//    }
//
//    @GetMapping("/user")
//    public ResponseEntity<Map<String, Object>> getUser(
//            @AuthenticationPrincipal OAuth2User oauth2User,
//            @AuthenticationPrincipal OidcUser oidcUser,
//            Authentication authentication) {
//
//        if (authentication == null || !authentication.isAuthenticated()) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
//        }
//
//        Map<String, Object> userInfo = new HashMap<>();
//
//        if (oidcUser != null) {
//            userInfo.put("name", oidcUser.getFullName());
//            userInfo.put("email", oidcUser.getEmail());
//            userInfo.put("username", oidcUser.getPreferredUsername());
//            userInfo.put("sub", oidcUser.getSubject());
//            userInfo.put("claims", oidcUser.getClaims());
//            userInfo.put("authorities", oidcUser.getAuthorities());
//            userInfo.put("type", "OIDC");
//        } else if (oauth2User != null) {
//            userInfo.put("name", oauth2User.getName());
//            userInfo.put("attributes", oauth2User.getAttributes());
//            userInfo.put("authorities", oauth2User.getAuthorities());
//            userInfo.put("type", "OAuth2");
//        } else {
//            userInfo.put("name", authentication.getName());
//            userInfo.put("authorities", authentication.getAuthorities());
//            userInfo.put("type", "Basic");
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
//
//    @GetMapping("/status")
//    public ResponseEntity<Map<String, Object>> getAuthStatus(Authentication authentication) {
//        Map<String, Object> status = new HashMap<>();
//        status.put("authenticated", authentication != null && authentication.isAuthenticated());
//        if (authentication != null) {
//            status.put("name", authentication.getName());
//            status.put("authorities", authentication.getAuthorities());
//        }
//        return ResponseEntity.ok(status);
//    }
//}

package com.customoauth2.customAuth20.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class AuthController {

    @GetMapping("/login")
    public void login(HttpServletResponse response) {
        // Redirect to OAuth2 login
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", "/oauth2/authorization/client-app");
    }

    @GetMapping("/user")
    public ResponseEntity<Map<String, Object>> getUser(
            @AuthenticationPrincipal OAuth2User oauth2User,
            Authentication authentication) {

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Map<String, Object> userInfo = new HashMap<>();
        if (oauth2User != null) {
            userInfo.put("name", oauth2User.getName());
            userInfo.put("attributes", oauth2User.getAttributes());
            userInfo.put("authorities", oauth2User.getAuthorities());
        } else {
            userInfo.put("name", authentication.getName());
            userInfo.put("authorities", authentication.getAuthorities());
        }

        return ResponseEntity.ok(userInfo);
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
        return ResponseEntity.ok(result);
    }
}
