package com.example.authserver.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

public class OidcSavedRequestSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    private final RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {
        SavedRequest saved = requestCache.getRequest(request, response);

        if (saved != null) {
            String target = saved.getRedirectUrl();
            // Helpful log in server output
            System.out.println("[LOGIN OK] Resuming saved request: " + target);
            // If it’s the authorization endpoint, send the browser there
            if (target.contains("/oauth2/authorize")) {
                getRedirectStrategy().sendRedirect(request, response, target);
                return;
            }
        }
        // Fallback: behave like default (to "/")
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
