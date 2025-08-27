//package com.example.customoauth.client.web;
//
//import org.springframework.http.HttpStatusCode;
//import org.springframework.http.MediaType;
//import org.springframework.security.core.annotation.AuthenticationPrincipal;
//import org.springframework.security.oauth2.core.oidc.user.OidcUser;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RestController;
//import org.springframework.web.reactive.function.client.WebClient;
//import reactor.core.publisher.Mono;
//
//@RestController
//public class ResourceProxyController {
//
//    private final WebClient resourceWebClient;
//
//    public ResourceProxyController(WebClient resourceWebClient) {
//        this.resourceWebClient = resourceWebClient;
//    }
//
//    @GetMapping(value = "/call-resource", produces = MediaType.APPLICATION_JSON_VALUE)
//    public Mono<String> callResource(@AuthenticationPrincipal OidcUser user) {
//        return resourceWebClient
//                .get()
//                .uri("/api/hello")
//                .retrieve()
//                .onStatus(
//                        HttpStatusCode::isError,
//                        resp -> resp.bodyToMono(String.class)
//                                .defaultIfEmpty("")
//                                .map(body -> new RuntimeException(
//                                        "Resource call failed: " + resp.statusCode() + " " + body))
//                )
//                .bodyToMono(String.class);
//    }
//}

//
//package com.example.customoauth.client.web;
//
//import org.springframework.http.HttpStatusCode;
//import org.springframework.http.MediaType;
//import org.springframework.security.core.annotation.AuthenticationPrincipal;
//import org.springframework.security.oauth2.core.oidc.user.OidcUser;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RestController;
//import org.springframework.web.reactive.function.client.WebClient;
//import reactor.core.publisher.Mono;
//
//@RestController
//public class ResourceProxyController {
//
//    private final WebClient resourceWebClient;
//
//    public ResourceProxyController(WebClient resourceWebClient) {
//        this.resourceWebClient = resourceWebClient;
//    }
//
//    @GetMapping(value = "/call-resource", produces = MediaType.APPLICATION_JSON_VALUE)
//    public Mono<String> callResource(@AuthenticationPrincipal OidcUser user) {
//        return resourceWebClient
//                .get()
//                .uri("/api/hello")
//                .retrieve()
//                .onStatus(
//                        HttpStatusCode::isError,
//                        resp -> resp.bodyToMono(String.class)
//                                .defaultIfEmpty("")
//                                .map(body -> new RuntimeException(
//                                        "Resource call failed: " + resp.statusCode() + " " + body))
//                )
//                .bodyToMono(String.class);
//    }
//}

//package com.example.customoauth.client.web;
//
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.MediaType;
//import org.springframework.security.core.annotation.AuthenticationPrincipal;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
//import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
//import org.springframework.security.oauth2.core.oidc.user.OidcUser;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RestController;
//import org.springframework.web.reactive.function.client.WebClient;
//import reactor.core.publisher.Mono;
//
//@RestController
//public class ResourceProxyController {
//
//    private final WebClient webClient; // plain WebClient bean (builder) or inject your existing one
//
//    public ResourceProxyController(WebClient.Builder builder) {
//        this.webClient = builder.build();
//    }
//
//    @GetMapping(value = "/call-resource", produces = MediaType.APPLICATION_JSON_VALUE)
//    public Mono<String> callResource(
//            @AuthenticationPrincipal OidcUser user,
//            @RegisteredOAuth2AuthorizedClient("generic") OAuth2AuthorizedClient client
//    ) {
//        String token = client.getAccessToken().getTokenValue();
//        return webClient.get()
//                .uri("http://localhost:8081/api/hello")
//                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
//                .retrieve()
//                .bodyToMono(String.class);
//    }
//}
//



//package com.example.customoauth.client.web;
//
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.MediaType;
//import org.springframework.security.core.annotation.AuthenticationPrincipal;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
//import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
//import org.springframework.security.oauth2.core.oidc.user.OidcUser;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RestController;
//import org.springframework.web.reactive.function.client.WebClient;
//import reactor.core.publisher.Mono;
//
//@RestController
//public class ResourceProxyController {
//
//    private final WebClient webClient;
//
//    public ResourceProxyController(WebClient.Builder builder) {
//        this.webClient = builder.build(); // plain builder – no oauth2 filter
//    }
//
//    @GetMapping(value = "/call-resource", produces = MediaType.APPLICATION_JSON_VALUE)
//    public Mono<String> callResource(
//            @AuthenticationPrincipal OidcUser user,
//            @RegisteredOAuth2AuthorizedClient("generic") OAuth2AuthorizedClient client
//    ) {
//        String token = client.getAccessToken().getTokenValue();
//        return webClient.get()
//                .uri("http://localhost:8081/api/hello")
//                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
//                .retrieve()
//                .bodyToMono(String.class);
//    }
//}




package com.example.customoauth.client.web;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@RestController
public class ResourceProxyController {

    private final WebClient webClient;

    public ResourceProxyController(WebClient.Builder builder) {
        this.webClient = builder.build(); // plain WebClient
    }

    @GetMapping(value = "/call-resource", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<String> callResource(
            @AuthenticationPrincipal OidcUser user,
            @RegisteredOAuth2AuthorizedClient("generic") OAuth2AuthorizedClient client
    ) {
        String token = client.getAccessToken().getTokenValue();
        return webClient.get()
                .uri("http://localhost:8081/api/hello")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .bodyToMono(String.class);
    }


}
