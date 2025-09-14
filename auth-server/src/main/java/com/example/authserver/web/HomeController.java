package com.example.authserver.web;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
    @GetMapping("/")
    public String home(Authentication auth) {
        System.out.println("Oauth"+ auth);
        return auth != null ? ("Signed in as " + auth.getName()) : "OK";
    }
}
