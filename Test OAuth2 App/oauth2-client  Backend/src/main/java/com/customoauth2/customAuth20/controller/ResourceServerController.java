package com.customoauth2.customAuth20.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/resource")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class ResourceServerController {

    private final WebClient webClient;

    @Autowired
    public ResourceServerController(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.baseUrl("http://localhost:8082").build();
    }

    @GetMapping("/greeting")
    public Mono<ResponseEntity<Object>> getGreeting(
            @RegisteredOAuth2AuthorizedClient("client-app") OAuth2AuthorizedClient authorizedClient) {

        if (authorizedClient == null) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "No authorized client found");
            error.put("message", "Please login first");
            return Mono.just(ResponseEntity.badRequest().body(error));
        }

        return webClient
                .get()
                .uri("/greeting")
                .headers(headers -> headers.setBearerAuth(authorizedClient.getAccessToken().getTokenValue()))
                .retrieve()
                .bodyToMono(String.class)
                .map(response -> {
                    Map<String, Object> result = new HashMap<>();
                    result.put("message", "Data from Resource Server");
                    result.put("greeting", response);
                    result.put("tokenType", authorizedClient.getAccessToken().getTokenType().getValue());
                    result.put("scopes", authorizedClient.getAccessToken().getScopes());
                    return ResponseEntity.ok((Object) result);
                })
                .onErrorResume(error -> {
                    Map<String, Object> errorResponse = new HashMap<>();
                    errorResponse.put("error", "Failed to call resource server");
                    errorResponse.put("message", error.getMessage());
                    return Mono.just(ResponseEntity.badRequest().body(errorResponse));
                });
    }

    @GetMapping("/me")
    public Mono<ResponseEntity<Object>> getResourceMe(
            @RegisteredOAuth2AuthorizedClient("client-app") OAuth2AuthorizedClient authorizedClient) {

        if (authorizedClient == null) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "No authorized client found");
            return Mono.just(ResponseEntity.badRequest().body(error));
        }

        return webClient
                .get()
                .uri("/me")
                .headers(headers -> headers.setBearerAuth(authorizedClient.getAccessToken().getTokenValue()))
                .retrieve()
                .bodyToMono(Map.class)
                .map(response -> {
                    Map<String, Object> result = new HashMap<>();
                    result.put("message", "User data from Resource Server");
                    result.put("data", response);
                    return ResponseEntity.ok((Object) result);
                })
                .onErrorResume(error -> {
                    Map<String, Object> errorResponse = new HashMap<>();
                    errorResponse.put("error", "Failed to call resource server /me endpoint");
                    errorResponse.put("message", error.getMessage());
                    return Mono.just(ResponseEntity.badRequest().body(errorResponse));
                });
    }
}
