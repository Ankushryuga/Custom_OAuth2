//package com.example.customoauth.client.web;
//import org.springframework.beans.factory.annotation.Value; import org.springframework.stereotype.Controller; import org.springframework.ui.Model; import org.springframework.web.bind.annotation.GetMapping; import org.springframework.web.reactive.function.client.WebClient;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClient; import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
//import org.springframework.security.oauth2.core.oidc.user.OidcUser; import org.springframework.security.core.annotation.AuthenticationPrincipal; import java.util.Map;
//@Controller public class HomeController {
//  private final WebClient webClient; public HomeController(WebClient.Builder b){ this.webClient = b.build(); }
//  @Value("${app.resource.base-uri:http://resource-server:8081}") private String resourceBaseUri;
//  @GetMapping("/") public String index(){ return "index"; }
//  @GetMapping("/call-resource") public String callResource(Model model, @RegisteredOAuth2AuthorizedClient("generic") OAuth2AuthorizedClient ac){
//    Map response = this.webClient.get().uri(resourceBaseUri + "/api/hello")
//      .attributes(org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(ac))
//      .retrieve().bodyToMono(Map.class).block();
//    model.addAttribute("resourceResponse", response); return "resource"; }
//  @GetMapping("/me") public String me(Model model, @AuthenticationPrincipal OidcUser user){ model.addAttribute("claims", user.getClaims()); return "me"; }
//}


//package com.example.customoauth.client.web;
//import org.springframework.beans.factory.annotation.Value; import org.springframework.stereotype.Controller; import org.springframework.ui.Model; import org.springframework.web.bind.annotation.GetMapping; import org.springframework.web.reactive.function.client.WebClient;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClient; import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
//import org.springframework.security.oauth2.core.oidc.user.OidcUser; import org.springframework.security.core.annotation.AuthenticationPrincipal; import java.util.Map;
//@Controller public class HomeController {
//  private final WebClient webClient; public HomeController(WebClient.Builder b){ this.webClient = b.build(); }
//  @Value("${app.resource.base-uri:http://resource-server:8081}") private String resourceBaseUri;
//  @GetMapping("/") public String index(){ return "index"; }
//  @GetMapping("/call-resource") public String callResource(Model model, @RegisteredOAuth2AuthorizedClient("generic") OAuth2AuthorizedClient ac){
//    Map response = this.webClient.get().uri(resourceBaseUri + "/api/hello")
//            .attributes(org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(ac))
//            .retrieve().bodyToMono(Map.class).block();
//    model.addAttribute("resourceResponse", response); return "resource"; }
//  @GetMapping("/me") public String me(Model model, @AuthenticationPrincipal OidcUser user){ model.addAttribute("claims", user.getClaims()); return "me"; }
//}



package com.example.customoauth.client.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Controller
public class HomeController {

  private final WebClient webClient;

  @Value("${app.resource.base-uri:http://localhost:8081}")
  private String resourceBaseUri;

  public HomeController(WebClient.Builder builder) {
    this.webClient = builder.build(); // plain WebClient; we'll set Bearer per request
  }

  @GetMapping("/")
  public String index() {
    return "index";
  }

  @GetMapping("/me")
  public String me(Model model, @AuthenticationPrincipal OidcUser user) {
    model.addAttribute("claims", user.getClaims());
    return "me";
  }

//  @GetMapping("/call-resource")
//  public String callResource(Model model,
//                             @RegisteredOAuth2AuthorizedClient("generic") OAuth2AuthorizedClient client) {
//
//    String token = client.getAccessToken().getTokenValue();
//
//    // --- Debug print (once) to verify token header/claims ---
//    try {
//      if (token.contains(".")) {
//        String[] parts = token.split("\\.");
//        String hdr = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
//        String cls = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
//        System.out.println("ACCESS TOKEN HEADER: " + hdr);   // look for "kid"
//        System.out.println("ACCESS TOKEN CLAIMS: " + cls);   // look for "iss":"http://localhost:9000"
//      } else {
//        System.out.println("ACCESS TOKEN IS OPAQUE (no dots)!");
//      }
//    } catch (Exception ignore) {}
//
//    // --- Call the resource and handle errors without throwing ---
//    try {
//      Map<?, ?> response = this.webClient.get()
//              .uri(resourceBaseUri + "/api/hello")
//              .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
//              .accept(MediaType.APPLICATION_JSON)
//              .exchangeToMono(clientResp -> {
//                if (clientResp.statusCode().is2xxSuccessful()) {
//                  return clientResp.bodyToMono(Map.class);
//                } else {
//                  return clientResp.bodyToMono(String.class)
//                          .defaultIfEmpty("")
//                          .map(body -> Map.of(
//                                  "error", "Resource call failed",
//                                  "status", clientResp.statusCode().value(),
//                                  "details", body));
//                }
//              })
//              .onErrorResume(ex -> Mono.just(Map.of(
//                      "error", "Client error",
//                      "details", ex.getMessage())))
//              .block();
//
//      model.addAttribute("resourceResponse", response);
//      model.addAttribute("errorMessage", null);
//    } catch (Exception ex) {
//      model.addAttribute("resourceResponse", null);
//      model.addAttribute("errorMessage", "Failed to call resource: " + ex.getMessage());
//    }
//
//    return "resource";
//  }

  @GetMapping("/call-resource")
  public String callResource(Model model,
                             @RegisteredOAuth2AuthorizedClient("generic") OAuth2AuthorizedClient client) {

    String token = client.getAccessToken().getTokenValue();

    // --- DEBUG: print the token header/claims once to your client logs ---
    try {
      if (token.contains(".")) {
        String[] parts = token.split("\\.");
        String hdr = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
        String cls = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        System.out.println("ACCESS TOKEN HEADER: " + hdr);   // look for "kid"
        System.out.println("ACCESS TOKEN CLAIMS: " + cls);   // look for "iss"
      } else {
        System.out.println("ACCESS TOKEN IS OPAQUE (no dots)!");
      }
    } catch (Exception ignore) {}

    try {
      Map<?, ?> response = this.webClient.get()
              .uri("http://localhost:8081/api/hello") // hard-code to avoid baseUri confusion
              .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
              .accept(MediaType.APPLICATION_JSON)
              .exchangeToMono(clientResp -> {
                if (clientResp.statusCode().is2xxSuccessful()) {
                  return clientResp.bodyToMono(Map.class);
                } else {
                  return clientResp.bodyToMono(String.class)
                          .defaultIfEmpty("")
                          .map(body -> Map.of(
                                  "error", "Resource call failed",
                                  "status", clientResp.statusCode().value(),
                                  "details", body));
                }
              })
              .onErrorResume(ex -> reactor.core.publisher.Mono.just(Map.of(
                      "error", "Client error",
                      "details", ex.getMessage())))
              .block();

      model.addAttribute("resourceResponse", response);
      model.addAttribute("errorMessage", null);
    } catch (Exception ex) {
      model.addAttribute("resourceResponse", null);
      model.addAttribute("errorMessage", "Failed to call resource: " + ex.getMessage());
    }

    return "resource";
  }

}
