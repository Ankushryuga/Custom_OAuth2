package com.example.authserver.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

@RestController
public class WhoController {

    private final AuthorizationServerSettings settings;

    public WhoController(AuthorizationServerSettings settings) {
        this.settings = settings;
    }

    @GetMapping("/__issuer")
    public String issuer() {
        String iss = settings.getIssuer();
        return iss == null ? "null" : iss;
    }
}
