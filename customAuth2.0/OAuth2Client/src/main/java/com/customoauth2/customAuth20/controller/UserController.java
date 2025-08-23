package com.customoauth2.customAuth20.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    @GetMapping("/me")
    public Object me(@AuthenticationPrincipal OidcUser oidcUser){
        return oidcUser != null? oidcUser.getClaims(): "No user logged in";
    }
}
