//////////// authorization-server/src/main/java/com/example/authorizationserver/web/LoginPageController.java
//////////package com.example.authorizationserver.web;
//////////
//////////import org.springframework.security.authentication.AnonymousAuthenticationToken;
//////////import org.springframework.security.core.Authentication;
//////////import org.springframework.security.web.csrf.CsrfToken;
//////////import org.springframework.stereotype.Controller;
//////////import org.springframework.web.bind.annotation.GetMapping;
//////////
//////////@Controller
//////////public class LoginPageController {
//////////
//////////    @GetMapping("/auth/login")
//////////    public String login(CsrfToken token, Authentication auth) {
//////////        // If already logged in, don't render the login page again.
//////////        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
//////////            return "redirect:/"; // or redirect to an admin page, or saved request
//////////        }
//////////        // Not authenticated: forward to your React login page entry
//////////        return "forward:/auth/login/index.html";
//////////    }
//////////}
////////
////////// authorization-server/src/main/java/com/example/authorizationserver/web/LoginPageController.java
////////package com.example.authorizationserver.web;
////////
////////import org.springframework.security.authentication.AnonymousAuthenticationToken;
////////import org.springframework.security.core.Authentication;
////////import org.springframework.security.web.csrf.CsrfToken;
////////import org.springframework.stereotype.Controller;
////////import org.springframework.web.bind.annotation.GetMapping;
////////
////////@Controller
////////public class LoginPageController {
////////
////////    @GetMapping("/auth/login")
////////    public String login(CsrfToken token, Authentication auth) {
////////        // touching 'token' ensures CookieCsrfTokenRepository writes XSRF-TOKEN cookie
////////        // If already authenticated, avoid showing the login page again
////////        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
////////            return "redirect:/";
////////        }
////////        // forward to the static React entry
////////        return "forward:/auth/login/index.html";
////////    }
////////}
//////
//////// authorization-server/src/main/java/com/example/authorizationserver/web/LoginPageController.java
//////package com.example.authorizationserver.web;
//////
//////import jakarta.servlet.http.HttpServletRequest;
//////import jakarta.servlet.http.HttpServletResponse;
//////import org.springframework.security.authentication.AnonymousAuthenticationToken;
//////import org.springframework.security.core.Authentication;
//////import org.springframework.security.web.csrf.CsrfToken;
//////import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//////import org.springframework.security.web.savedrequest.SavedRequest;
//////import org.springframework.stereotype.Controller;
//////import org.springframework.web.bind.annotation.GetMapping;
//////
//////@Controller
//////public class LoginPageController {
//////
//////    private final HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
//////
//////    @GetMapping("/auth/login")
//////    public String login(CsrfToken token, Authentication auth,
//////                        HttpServletRequest req, HttpServletResponse res) {
//////        // Accessing CsrfToken ensures CookieCsrfTokenRepository sets XSRF-TOKEN cookie.
//////        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
//////            // If we arrived here already authenticated, try to resume any saved request
//////            SavedRequest saved = requestCache.getRequest(req, res);
//////            if (saved != null) {
//////                String url = saved.getRedirectUrl();
//////                // Avoid loops to login helpers
//////                if (!url.contains("/auth/csrf") && !url.endsWith("/auth/login") && !url.contains("/oauth/login")) {
//////                    return "redirect:" + url;
//////                }
//////            }
//////            // No saved request: go to a neutral page within the AS
//////            return "redirect:/landing";
//////        }
//////        // Not authenticated: show the React login app
//////        return "forward:/auth/login/index.html";
//////    }
//////}
////
////package com.example.authorizationserver.web;
////
////import jakarta.servlet.http.HttpServletRequest;
////import jakarta.servlet.http.HttpServletResponse;
////import org.springframework.security.authentication.AnonymousAuthenticationToken;
////import org.springframework.security.core.Authentication;
////import org.springframework.security.web.csrf.CsrfToken;
////import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
////import org.springframework.security.web.savedrequest.SavedRequest;
////import org.springframework.stereotype.Controller;
////import org.springframework.web.bind.annotation.GetMapping;
////
////@Controller
////public class LoginPageController {
////
////    private final HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
////
////    /**
////     * GET /auth/login
////     * - If NOT authenticated: forward to the static React login page.
////     * - If authenticated: resume saved request (e.g., /oauth2/authorize) when present,
////     *   else go to a neutral internal page (/landing).
////     * Touching CsrfToken ensures XSRF-TOKEN cookie is set by CookieCsrfTokenRepository.
////     */
////    @GetMapping("/auth/login")
////    public String login(CsrfToken token, Authentication auth,
////                        HttpServletRequest req, HttpServletResponse res) {
////        boolean authenticated = auth != null && auth.isAuthenticated()
////                && !(auth instanceof AnonymousAuthenticationToken);
////
////        if (authenticated) {
////            SavedRequest saved = requestCache.getRequest(req, res);
////            if (saved != null) {
////                String url = saved.getRedirectUrl();
////                // Avoid loops to helper/login paths
////                if (!url.endsWith("/auth/login")
////                        && !url.contains("/auth/csrf")
////                        && !url.contains("/oauth/login")) {
////                    return "redirect:" + url; // resume authorize flow → client redirect_uri
////                }
////            }
////            return "redirect:/landing"; // neutral internal page
////        }
////
////        // Not authenticated → show React login (static)
////        return "forward:/auth/login/index.html";
////    }
////}
//
//
//package com.example.authorizationserver.web;
//
//import com.example.authorizationserver.config.AuthUiProperties;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.security.authentication.AnonymousAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.web.csrf.CsrfToken;
//import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//import org.springframework.security.web.savedrequest.SavedRequest;
//import org.springframework.stereotype.Controller;
//import org.springframework.web.bind.annotation.GetMapping;
//
//@Controller
//public class LoginPageController {
//
//    private final HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
//    private final AuthUiProperties ui;
//
//    public LoginPageController(AuthUiProperties ui) {
//        this.ui = ui;
//    }
//
//    /**
//     * GET /auth/login
//     * - If NOT authenticated: forward to the static React login page.
//     * - If authenticated: resume saved request (/oauth2/authorize) when present,
//     *   else redirect to configured default-success-url (e.g., http://localhost:5173/).
//     * Touching CsrfToken ensures XSRF-TOKEN cookie is set by CookieCsrfTokenRepository.
//     */
//    @GetMapping("/auth/login")
//    public String login(CsrfToken token, Authentication auth,
//                        HttpServletRequest req, HttpServletResponse res) {
//        boolean authenticated = auth != null && auth.isAuthenticated()
//                && !(auth instanceof AnonymousAuthenticationToken);
//
//        if (authenticated) {
//            SavedRequest saved = requestCache.getRequest(req, res);
//            if (saved != null) {
//                String url = saved.getRedirectUrl();
//                // Avoid loops to helper/login paths
//                if (!url.endsWith("/auth/login")
//                        && !url.contains("/auth/csrf")
//                        && !url.contains("/oauth/login")) {
//                    return "redirect:" + url; // resume authorize → client redirect_uri
//                }
//            }
//            // No saved request: go to the configured external default (from application.yml)
//            return "redirect:" + ui.getDefaultSuccessUrl();
//        }
//
//        // Not authenticated → show the React login (static)
//        return "forward:/auth/login/index.html";
//    }
//}


package com.example.authorizationserver.web;

import com.example.authorizationserver.config.AuthUiProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginPageController {

    private final HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
    private final AuthUiProperties ui;

    public LoginPageController(AuthUiProperties ui) {
        this.ui = ui;
    }

    @GetMapping("/auth/login")
    public String login(CsrfToken token, Authentication auth,
                        HttpServletRequest req, HttpServletResponse res) {
        boolean authenticated = auth != null && auth.isAuthenticated()
                && !(auth instanceof AnonymousAuthenticationToken);

        if (authenticated) {
            SavedRequest saved = requestCache.getRequest(req, res);
            if (saved != null) {
                String url = saved.getRedirectUrl();
                if (!url.endsWith("/auth/login")
                        && !url.contains("/auth/csrf")
                        && !url.contains("/oauth/login")) {
                    return "redirect:" + url; // resume authorize → client redirect_uri
                }
            }
            return "redirect:" + ui.getDefaultSuccessUrl(); // e.g., http://localhost:5173/
        }

        // Not authenticated → forward to static React login (if you ship it with AS)
        return "forward:/auth/login/index.html";
    }
}
