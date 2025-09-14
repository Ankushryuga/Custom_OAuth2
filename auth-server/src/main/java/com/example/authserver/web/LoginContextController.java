package com.example.authserver.web;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.beans.factory.annotation.Autowired;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static com.example.authserver.config.SecurityConfig.CONT_COOKIE;

@RestController
public class LoginContextController {

    private final RequestCache requestCache;

    @Autowired
    public LoginContextController(RequestCache requestCache) {
        this.requestCache = requestCache;
    }

    /** Allows the login page to read whichever resume URL is available. */
    @GetMapping("/login/context")
    public Map<String, String> context(HttpServletRequest req, HttpServletResponse res) {
        SavedRequest saved = requestCache.getRequest(req, res);
        if (saved != null && isAuthorizeUrl(saved.getRedirectUrl())) {
            return Map.of("continue", saved.getRedirectUrl());
        }
        String c = readCookie(req, CONT_COOKIE);
        if (c != null && !c.isBlank()) {
            String cont = URLDecoder.decode(c, StandardCharsets.UTF_8);
            if (isAuthorizeUrl(cont)) return Map.of("continue", cont);
        }
        return Map.of("continue", "");
    }

    private static boolean isAuthorizeUrl(String url) {
        try { return "/oauth2/authorize".equals(URI.create(url).getPath()); }
        catch (Exception e) { return false; }
    }

    private static String readCookie(HttpServletRequest req, String name) {
        Cookie[] cs = req.getCookies(); if (cs == null) return null;
        for (Cookie k : cs) if (name.equals(k.getName())) return k.getValue();
        return null;
    }
}
