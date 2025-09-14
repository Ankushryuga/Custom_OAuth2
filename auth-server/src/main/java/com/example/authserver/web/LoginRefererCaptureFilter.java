package com.example.authserver.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Last-chance safety net: if we arrive at GET /login with a Referer that is /oauth2/authorize,
 * set the CONTINUE cookie so the success handler can still resume the flow.
 */
public class LoginRefererCaptureFilter extends OncePerRequestFilter {

    private final String cookieName;

    public LoginRefererCaptureFilter(String cookieName) {
        this.cookieName = cookieName;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"GET".equalsIgnoreCase(request.getMethod())
                || !"/login".equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String ref = req.getHeader("Referer");
        if (ref != null && !ref.isBlank()) {
            try {
                URI u = URI.create(ref);
                if ("/oauth2/authorize".equals(u.getPath())) {
                    Cookie c = new Cookie(cookieName, URLEncoder.encode(ref, StandardCharsets.UTF_8));
                    c.setHttpOnly(true);
                    c.setPath("/");
                    c.setMaxAge(120);
                    res.addCookie(c);
                }
            } catch (Exception ignore) {}
        }
        chain.doFilter(req, res);
    }
}
