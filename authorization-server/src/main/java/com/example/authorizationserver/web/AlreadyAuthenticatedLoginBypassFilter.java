// authorization-server/src/main/java/com/example/authorizationserver/web/AlreadyAuthenticatedLoginBypassFilter.java
package com.example.authorizationserver.web;

import com.example.authorizationserver.config.AuthUiProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class AlreadyAuthenticatedLoginBypassFilter extends OncePerRequestFilter {
    private static final AntPathMatcher matcher = new AntPathMatcher();
    private final String defaultSuccessUrl;

    public AlreadyAuthenticatedLoginBypassFilter(String defaultSuccessUrl) {
        this.defaultSuccessUrl = (defaultSuccessUrl == null || defaultSuccessUrl.isBlank()) ? "/" : defaultSuccessUrl;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        boolean isLoginPost = "POST".equalsIgnoreCase(request.getMethod())
                && matcher.match("/login", request.getServletPath());

        if (isLoginPost) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated()) {
                // Already logged in: avoid re-auth + CSRF error; go to configured fallback (relative)
                String ctx = request.getContextPath(); // usually ""
                response.sendRedirect(ctx + defaultSuccessUrl);
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
