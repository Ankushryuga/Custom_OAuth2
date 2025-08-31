package com.example.client.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestClient;

import java.util.Map;

@Controller
public class HomeController {

    private final RestClient restClient = RestClient.builder().build();

    @GetMapping("/")
    public String home(@AuthenticationPrincipal OidcUser user, Model model) {
        model.addAttribute("user", user);
        return "index";
    }

    @GetMapping("/call-rs")
    public String callResourceServer(@RegisteredOAuth2AuthorizedClient("client-app") OAuth2AuthorizedClient client,
                                     Model model) {
        String token = client.getAccessToken().getTokenValue();
        ResponseEntity<Map> resp = restClient.get()
                .uri("http://localhost:9090/api/hello")
                .header("Authorization", "Bearer " + token)
                .retrieve()
                .toEntity(Map.class);
        model.addAttribute("rs", resp.getBody());
        return "index";
    }
}
