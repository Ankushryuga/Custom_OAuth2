////package com.example.authserver.config;
////
////import com.example.authserver.support.FileBackedJwks;
////import com.example.authserver.web.LoginRefererCaptureFilter;
////import com.nimbusds.jose.jwk.source.JWKSource;
////import com.nimbusds.jose.proc.SecurityContext;
////import jakarta.servlet.http.Cookie;
////import jakarta.servlet.http.HttpServletRequest;
////import jakarta.servlet.http.HttpServletResponse;
////
////import javax.sql.DataSource;
////import java.net.URI;
////import java.net.URLDecoder;
////import java.nio.charset.StandardCharsets;
////import java.util.Arrays;
////import java.util.List;
////
////import org.springframework.beans.factory.annotation.Value;
////import org.springframework.context.annotation.Bean;
////import org.springframework.context.annotation.Configuration;
////import org.springframework.core.Ordered;
////import org.springframework.core.annotation.Order;
////import org.springframework.http.MediaType;
////import org.springframework.jdbc.core.JdbcTemplate;
////import org.springframework.security.config.Customizer;
////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////import org.springframework.security.core.userdetails.User;
////import org.springframework.security.core.userdetails.UserDetailsService;
////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
////import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
////import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
////import org.springframework.security.provisioning.InMemoryUserDetailsManager;
////import org.springframework.security.web.SecurityFilterChain;
////import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
////import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
////import org.springframework.security.web.savedrequest.RequestCache;
////import org.springframework.security.web.savedrequest.SavedRequest;
////import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
////import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
////import org.springframework.security.web.util.matcher.RequestMatcher;
////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
////import org.springframework.web.cors.CorsConfiguration;
////import org.springframework.web.cors.CorsConfigurationSource;
////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
////
////@Configuration
////@EnableWebSecurity
////public class SecurityConfig {
////
////  public static final String CONT_COOKIE = "CONTINUE";
////
////  /** Save ONLY GET /oauth2/authorize so noise can’t overwrite it. */
////  @Bean
////  RequestCache authorizeOnlyRequestCache() {
////    return new HttpSessionRequestCache() {
////      @Override
////      public void saveRequest(HttpServletRequest req, HttpServletResponse res) {
////        if ("GET".equalsIgnoreCase(req.getMethod())
////                && "/oauth2/authorize".equals(req.getRequestURI())) {
////          super.saveRequest(req, res);
////        }
////      }
////    };
////  }
////
////  /* ========= Authorization Server chain ========= */
////  @Bean
////  @Order(Ordered.HIGHEST_PRECEDENCE)
////  SecurityFilterChain authorizationServerSecurityFilterChain(
////          HttpSecurity http, RequestCache authorizeOnlyRequestCache) throws Exception {
////
////    // Let SAS register all its endpoint filters (incl. /oauth2/token POST)
////    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
////
////    // Turn on OIDC (/.well-known/openid-configuration, /userinfo, etc.)
////    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
////            .oidc(Customizer.withDefaults());
////
////    // Only HTML /oauth2/authorize requests should redirect to /login (browsers).
////    // Token POST remains JSON (no redirect), which avoids 405.
////    RequestMatcher htmlAny = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
////    http
////            .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
////                    new LoginUrlAuthenticationEntryPoint("/login"), htmlAny))
////            .requestCache(c -> c.requestCache(authorizeOnlyRequestCache))
////            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
////            .cors(Customizer.withDefaults());
////
////    return http.build();
////  }
////
////  /* ========= Application chain (login UI, static, DCR) ========= */
////  @Bean
////  SecurityFilterChain appSecurityFilterChain(
////          HttpSecurity http, RequestCache authorizeOnlyRequestCache) throws Exception {
////
////    // Capture Referer on GET /login as a last-chance resume source (sets CONTINUE cookie)
////    http.addFilterBefore(new LoginRefererCaptureFilter(CONT_COOKIE),
////            UsernamePasswordAuthenticationFilter.class);
////
////    // Prefer SavedRequest; fallback to cookie; lastly accept posted ?continue=
////    var savedHandler = new SavedRequestAwareAuthenticationSuccessHandler() {
////      @Override
////      protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
////        // 1) SavedRequest (/oauth2/authorize only)
////        SavedRequest saved = authorizeOnlyRequestCache.getRequest(request, response);
////        if (saved != null && isAuthorizeUrl(saved.getRedirectUrl())) {
////          return saved.getRedirectUrl();
////        }
////        // 2) Cookie fallback
////        String contCookie = readCookie(request, CONT_COOKIE);
////        if (contCookie != null && !contCookie.isBlank()) {
////          String cont = URLDecoder.decode(contCookie, StandardCharsets.UTF_8);
////          if (sameOrigin(cont, request) && isAuthorizeUrl(cont)) return cont;
////        }
////        // 3) Posted hidden field from the login form
////        String posted = request.getParameter("continue");
////        if (posted != null && !posted.isBlank() && sameOrigin(posted, request) && isAuthorizeUrl(posted)) {
////          return posted;
////        }
////        return null;
////      }
////    };
////
////    http
////            .authorizeHttpRequests(auth -> auth
////                    .requestMatchers(
////                            new AntPathRequestMatcher("/connect/**"),
////                            new AntPathRequestMatcher("/actuator/**"),
////                            new AntPathRequestMatcher("/login"),
////                            new AntPathRequestMatcher("/login/**"),
////                            new AntPathRequestMatcher("/login/context"),
////                            new AntPathRequestMatcher("/assets/**"),
////                            new AntPathRequestMatcher("/csrf"),
////                            new AntPathRequestMatcher("/"),
////                            new AntPathRequestMatcher("/favicon.ico"),
////                            new AntPathRequestMatcher("/manifest*"),
////                            new AntPathRequestMatcher("/robots.txt"),
////                            new AntPathRequestMatcher("/.well-known/**")
////                    ).permitAll()
////                    .anyRequest().authenticated()
////            )
////            .formLogin(form -> form
////                    .loginPage("/login")
////                    .loginProcessingUrl("/login")
////                    .successHandler((request, response, authentication) -> {
////                      String target = savedHandler.determineTargetUrl(request, response);
////                      if (target != null) {
////                        Cookie del = new Cookie(CONT_COOKIE, ""); del.setPath("/"); del.setMaxAge(0); response.addCookie(del);
////                        response.sendRedirect(target);
////                        return;
////                      }
////                      response.setStatus(400);
////                      response.setContentType("text/plain;charset=UTF-8");
////                      response.getWriter().write(
////                              "Login OK, but no original /oauth2/authorize request was found in session or cookie. " +
////                                      "Please start from your application — it must call /oauth2/authorize with redirect_uri."
////                      );
////                    })
////                    .failureUrl("/login?error")
////                    .permitAll()
////            )
////            .requestCache(c -> c.requestCache(authorizeOnlyRequestCache))
//////            .csrf(csrf -> csrf
//////                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//////                    .ignoringRequestMatchers(new AntPathRequestMatcher("/connect/**"))
//////            )
////            .csrf(csrf -> csrf.disable())
////            .cors(Customizer.withDefaults());
////
////    return http.build();
////  }
////
////  /* ========= CORS (generic multi-client) ========= */
//////  @Bean
//////  CorsConfigurationSource corsConfigurationSource(
//////          @Value("${CORS_ALLOWED_ORIGINS:}") String originsProperty) {
//////
//////    var cfg = new CorsConfiguration();
//////    cfg.setAllowCredentials(true);
//////
//////    var configured = Arrays.stream(originsProperty.split(","))
//////            .map(String::trim).filter(s -> !s.isEmpty()).toList();
//////
//////    if (configured.isEmpty()) {
//////      cfg.setAllowedOriginPatterns(List.of(
//////              "http://localhost:*",
//////              "http://127.0.0.1:*",
//////              "https://*.localtest.me"
//////      ));
//////    } else {
//////      cfg.setAllowedOriginPatterns(configured);
//////    }
//////
//////    cfg.setAllowedMethods(List.of("GET","POST","OPTIONS"));
//////    cfg.setAllowedHeaders(List.of("Authorization","Content-Type","X-Requested-With","X-CSRF-TOKEN"));
//////
//////    var src = new UrlBasedCorsConfigurationSource();
//////    src.registerCorsConfiguration("/**", cfg);
//////    return src;
//////  }
////
//////  @Bean
//////  CorsConfigurationSource corsConfigurationSource(
//////          @Value("${CORS_ALLOWED_ORIGINS:}") String originsProperty) {
//////
//////    CorsConfiguration cfg = new CorsConfiguration();
//////    cfg.setAllowCredentials(true);
//////
//////    var configured = Arrays.stream(originsProperty.split(","))
//////            .map(String::trim).filter(s -> !s.isEmpty()).toList();
//////
//////    if (configured.isEmpty()) {
//////      cfg.setAllowedOriginPatterns(List.of(
//////              "http://localhost:*",
//////              "http://127.0.0.1:*",
//////              "https://*.localtest.me"
//////      ));
//////    } else {
//////      cfg.setAllowedOriginPatterns(configured);
//////    }
//////
//////    // 🔧 Be permissive to avoid odd 405/blocked preflights across endpoints
//////    cfg.addAllowedHeader("*");
//////    cfg.addAllowedMethod("*");   // GET, POST, OPTIONS, etc.
//////
//////    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
//////    src.registerCorsConfiguration("/**", cfg);
//////    return src;
//////  }
//////
////
////  @Bean
////  public CorsConfigurationSource corsConfigurationSource() {
////    CorsConfiguration cfg = new CorsConfiguration();
////    cfg.setAllowedOrigins(List.of("*"));                 // any origin
////    cfg.setAllowedMethods(List.of("GET","POST","PUT","PATCH","DELETE","OPTIONS"));
////    cfg.setAllowedHeaders(List.of("*"));
////    cfg.setExposedHeaders(List.of("*"));
////    cfg.setAllowCredentials(false);                      // required when using "*"
////    cfg.setMaxAge(3600L);
////
////    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
////    src.registerCorsConfiguration("/**", cfg);           // includes /.well-known, /oauth2, /connect, etc.
////    return src;
////  }
////
////  /* ========= Authorization Server infra ========= */
////  @Bean
////  AuthorizationServerSettings authorizationServerSettings(
////          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer) {
////    return AuthorizationServerSettings.builder().issuer(issuer).build();
////  }
////
////  @Bean JWKSource<SecurityContext> jwkSource(@Value("${auth.jwks.dir:./data/jwks}") String dir) {
////    return new FileBackedJwks(dir);
////  }
////
////  @Bean RegisteredClientRepository registeredClientRepository(DataSource ds) {
////    return new JdbcRegisteredClientRepository(new JdbcTemplate(ds));
////  }
////
////  @Bean OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
////    return new JdbcOAuth2AuthorizationService(jdbc, repo);
////  }
////
////  @Bean OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
////    return new JdbcOAuth2AuthorizationConsentService(jdbc, repo);
////  }
////
////  @Bean
////  UserDetailsService users() {
////    return new InMemoryUserDetailsManager(
////            User.withUsername("user").password("{noop}password").roles("USER").build()
////    );
////  }
////
////  /* ===== helpers ===== */
////  private static boolean isAuthorizeUrl(String url) {
////    try { return "/oauth2/authorize".equals(URI.create(url).getPath()); }
////    catch (Exception e) { return false; }
////  }
////  private static String readCookie(HttpServletRequest req, String name) {
////    Cookie[] cs = req.getCookies(); if (cs == null) return null;
////    for (Cookie c : cs) if (name.equals(c.getName())) return c.getValue();
////    return null;
////  }
////  private static boolean sameOrigin(String url, HttpServletRequest req) {
////    try {
////      URI u = URI.create(url);
////      if (!u.isAbsolute()) return true;
////      String host = req.getServerName();
////      int port  = req.getServerPort();
////      return host.equalsIgnoreCase(u.getHost()) && (u.getPort() == -1 || u.getPort() == port);
////    } catch (Exception e) { return false; }
////  }
////}
//
//package com.example.authserver.config;
//
//import com.example.authserver.support.FileBackedJwks;
//import com.example.authserver.web.LoginRefererCaptureFilter;
//import com.nimbusds.jose.jwk.source.JWKSource;
//import com.nimbusds.jose.proc.SecurityContext;
//import jakarta.servlet.http.Cookie;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//
//import javax.sql.DataSource;
//import java.net.URI;
//import java.net.URLDecoder;
//import java.nio.charset.StandardCharsets;
//import java.util.List;
//
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Primary;
//import org.springframework.core.Ordered;
//import org.springframework.core.annotation.Order;
//import org.springframework.http.MediaType;
//import org.springframework.jdbc.core.JdbcTemplate;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
//import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
//import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
//import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
//import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
//import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//import org.springframework.security.web.savedrequest.RequestCache;
//import org.springframework.security.web.savedrequest.SavedRequest;
//import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
//import org.springframework.security.web.util.matcher.RequestMatcher;
//import org.springframework.web.cors.CorsConfiguration;
//import org.springframework.web.cors.CorsConfigurationSource;
//import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//  public static final String CONT_COOKIE = "CONTINUE";
//
//  /** Keep only GET /oauth2/authorize in SavedRequest so noise can't overwrite it. */
//  @Bean
//  RequestCache authorizeOnlyRequestCache() {
//    return new HttpSessionRequestCache() {
//      @Override
//      public void saveRequest(HttpServletRequest req, HttpServletResponse res) {
//        if ("GET".equalsIgnoreCase(req.getMethod())
//                && "/oauth2/authorize".equals(req.getRequestURI())) {
//          super.saveRequest(req, res);
//        }
//      }
//    };
//  }
//
//  /* ===================== Authorization Server chain ===================== */
//  @Bean
//  @Order(Ordered.HIGHEST_PRECEDENCE)
//  SecurityFilterChain authorizationServerSecurityFilterChain(
//          HttpSecurity http, RequestCache authorizeOnlyRequestCache) throws Exception {
//
//    // Register default SAS endpoints (/oauth2/token, etc.)
//    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//
//    // Enable OIDC (/.well-known/openid-configuration, /userinfo, etc.)
//    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//            .oidc(Customizer.withDefaults());
//
//    // HTML requests to AS should redirect to /login; token POST stays JSON (no redirect)
//    RequestMatcher htmlAny = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
//
//    http
//            .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
//                    new LoginUrlAuthenticationEntryPoint("/login"), htmlAny))
//            .requestCache(c -> c.requestCache(authorizeOnlyRequestCache))
//            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
//            .cors(Customizer.withDefaults()); // apply global CORS
//
//    return http.build();
//  }
//
//  /* ===================== Application chain (login, static, DCR) ===================== */
//  @Bean
//  SecurityFilterChain appSecurityFilterChain(
//          HttpSecurity http, RequestCache authorizeOnlyRequestCache) throws Exception {
//
//    // Capture Referer on GET /login as a fallback to resume consent
//    http.addFilterBefore(new LoginRefererCaptureFilter(CONT_COOKIE),
//            UsernamePasswordAuthenticationFilter.class);
//
//    // Decide where to go after login
//    var savedHandler = new SavedRequestAwareAuthenticationSuccessHandler() {
//      @Override
//      protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
//        // 1) SavedRequest (/oauth2/authorize only)
//        SavedRequest saved = authorizeOnlyRequestCache.getRequest(request, response);
//        if (saved != null && isAuthorizeUrl(saved.getRedirectUrl())) {
//          return saved.getRedirectUrl();
//        }
//        // 2) Cookie fallback
//        String contCookie = readCookie(request, CONT_COOKIE);
//        if (contCookie != null && !contCookie.isBlank()) {
//          String cont = URLDecoder.decode(contCookie, StandardCharsets.UTF_8);
//          if (sameOrigin(cont, request) && isAuthorizeUrl(cont)) return cont;
//        }
//        // 3) Posted hidden field from the login form
//        String posted = request.getParameter("continue");
//        if (posted != null && !posted.isBlank() && sameOrigin(posted, request) && isAuthorizeUrl(posted)) {
//          return posted;
//        }
//        return null;
//      }
//    };
//
//    http
//            .authorizeHttpRequests(auth -> auth
//                    .requestMatchers(
//                            new AntPathRequestMatcher("/connect/**"),
//                            new AntPathRequestMatcher("/actuator/**"),
//                            new AntPathRequestMatcher("/login"),
//                            new AntPathRequestMatcher("/login/**"),
//                            new AntPathRequestMatcher("/login/context"),
//                            new AntPathRequestMatcher("/assets/**"),
//                            new AntPathRequestMatcher("/csrf"),
//                            new AntPathRequestMatcher("/"),
//                            new AntPathRequestMatcher("/favicon.ico"),
//                            new AntPathRequestMatcher("/manifest*"),
//                            new AntPathRequestMatcher("/robots.txt"),
//                            new AntPathRequestMatcher("/.well-known/**")
//                    ).permitAll()
//                    .anyRequest().authenticated()
//            )
//            .formLogin(form -> form
//                    .loginPage("/login")
//                    .loginProcessingUrl("/login")
//                    .successHandler((request, response, authentication) -> {
//                      String target = savedHandler.determineTargetUrl(request, response);
//                      if (target != null) {
//                        Cookie del = new Cookie(CONT_COOKIE, "");
//                        del.setPath("/");
//                        del.setMaxAge(0);
//                        response.addCookie(del);
//                        response.sendRedirect(target);
//                        return;
//                      }
//                      response.setStatus(400);
//                      response.setContentType("text/plain;charset=UTF-8");
//                      response.getWriter().write(
//                              "Login OK, but no original /oauth2/authorize request was found in session or cookie. " +
//                                      "Please start from your application — it must call /oauth2/authorize with redirect_uri."
//                      );
//                    })
//                    .failureUrl("/login?error")
//                    .permitAll()
//            )
//            .requestCache(c -> c.requestCache(authorizeOnlyRequestCache))
//            .csrf(csrf -> csrf.disable())     // if you need CSRF, scope exceptions for /connect/**
//            .cors(Customizer.withDefaults());  // apply global CORS
//
//    return http.build();
//  }
//
//  /* ===================== CORS (global) ===================== */
//  @Bean
//  public CorsConfigurationSource corsConfigurationSource() {
//    CorsConfiguration cfg = new CorsConfiguration();
//
//    // DEV: allow any origin (no credentials). This fixes SPA discovery CORS quickly.
//    cfg.setAllowedOrigins(List.of("*"));
//    cfg.setAllowCredentials(false);       // must be false when using "*"
//    cfg.addAllowedMethod("*");            // GET, POST, PUT, PATCH, DELETE, OPTIONS
//    cfg.addAllowedHeader("*");
//    cfg.addExposedHeader("*");
//    cfg.setMaxAge(3600L);
//
//    // PROD: replace above with explicit origins & (optionally) credentials:
//    // cfg.setAllowedOriginPatterns(List.of("http://10.201.240.239:5174","http://localhost:5174"));
//    // cfg.setAllowCredentials(true);
//
//    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
//    src.registerCorsConfiguration("/**", cfg); // IMPORTANT: apply to everything (/.well-known, /oauth2, /connect, etc.)
//    return src;
//  }
//
//  /* ===================== Authorization Server infra ===================== */
////  @Bean
////  AuthorizationServerSettings authorizationServerSettings(
////          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer) {
////    // Set AUTH_ISSUER_URI=http://10.201.240.154:8080 in your env to match your IP setup
////    return AuthorizationServerSettings.builder().issuer(issuer).build();
////  }
//
//  @Primary
//  @Bean("authorizationServerSettings")  // force this bean to be used
//  AuthorizationServerSettings authorizationServerSettings(
//          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer) {
//    Logger log = LoggerFactory.getLogger(SecurityConfig.class);
//    log.info(">>> AUTH_ISSUER_URI in use: {}", issuer);
//    return AuthorizationServerSettings.builder().issuer(issuer).build();
//  }
//
//  @Bean
//  JWKSource<SecurityContext> jwkSource(@Value("${auth.jwks.dir:./data/jwks}") String dir) {
//    return new FileBackedJwks(dir);
//  }
//
//  @Bean
//  RegisteredClientRepository registeredClientRepository(DataSource ds) {
//    return new JdbcRegisteredClientRepository(new JdbcTemplate(ds));
//  }
//
//  @Bean
//  OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
//    return new JdbcOAuth2AuthorizationService(jdbc, repo);
//  }
//
//  @Bean
//  OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
//    return new JdbcOAuth2AuthorizationConsentService(jdbc, repo);
//  }
//
//  @Bean
//  UserDetailsService users() {
//    return new InMemoryUserDetailsManager(
//            User.withUsername("user").password("{noop}password").roles("USER").build()
//    );
//  }
//
//  /* ===================== helpers ===================== */
//  private static boolean isAuthorizeUrl(String url) {
//    try { return "/oauth2/authorize".equals(URI.create(url).getPath()); }
//    catch (Exception e) { return false; }
//  }
//
//  private static String readCookie(HttpServletRequest req, String name) {
//    Cookie[] cs = req.getCookies(); if (cs == null) return null;
//    for (Cookie c : cs) if (name.equals(c.getName())) return c.getValue();
//    return null;
//  }
//
//  private static boolean sameOrigin(String url, HttpServletRequest req) {
//    try {
//      URI u = URI.create(url);
//      if (!u.isAbsolute()) return true;
//      String host = req.getServerName();
//      int port  = req.getServerPort();
//      return host.equalsIgnoreCase(u.getHost()) && (u.getPort() == -1 || u.getPort() == port);
//    } catch (Exception e) { return false; }
//  }
//}

package com.example.authserver.config;

import com.example.authserver.support.FileBackedJwks;
import com.example.authserver.web.LoginRefererCaptureFilter;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.sql.DataSource;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);
  public static final String CONT_COOKIE = "CONTINUE";

  @Bean
  RequestCache authorizeOnlyRequestCache() {
    return new HttpSessionRequestCache() {
      @Override
      public void saveRequest(HttpServletRequest req, HttpServletResponse res) {
        if ("GET".equalsIgnoreCase(req.getMethod())
                && "/oauth2/authorize".equals(req.getRequestURI())) {
          super.saveRequest(req, res);
        }
      }
    };
  }

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  SecurityFilterChain authorizationServerSecurityFilterChain(
          HttpSecurity http,
          RequestCache authorizeOnlyRequestCache,
          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer
  ) throws Exception {

    // Register default endpoints
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    // Configure OIDC + **force issuer** directly
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults())
            .authorizationServerSettings(AuthorizationServerSettings.builder()
                    .issuer(issuer)
                    .build());
    log.info(">>> Authorization Server issuer in use: {}", issuer);

    // HTML requests to AS should go to /login; token endpoints remain JSON
    RequestMatcher htmlAny = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
    http
            .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"), htmlAny))
            .requestCache(c -> c.requestCache(authorizeOnlyRequestCache))
            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
            .cors(Customizer.withDefaults());

    return http.build();
  }

  @Bean
  SecurityFilterChain appSecurityFilterChain(
          HttpSecurity http, RequestCache authorizeOnlyRequestCache) throws Exception {

    http.addFilterBefore(new LoginRefererCaptureFilter(CONT_COOKIE),
            UsernamePasswordAuthenticationFilter.class);

    var savedHandler = new SavedRequestAwareAuthenticationSuccessHandler() {
      @Override
      protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest saved = authorizeOnlyRequestCache.getRequest(request, response);
        if (saved != null && isAuthorizeUrl(saved.getRedirectUrl())) return saved.getRedirectUrl();
        String contCookie = readCookie(request, CONT_COOKIE);
        if (contCookie != null && !contCookie.isBlank()) {
          String cont = URLDecoder.decode(contCookie, StandardCharsets.UTF_8);
          if (sameOrigin(cont, request) && isAuthorizeUrl(cont)) return cont;
        }
        String posted = request.getParameter("continue");
        if (posted != null && !posted.isBlank() && sameOrigin(posted, request) && isAuthorizeUrl(posted)) return posted;
        return null;
      }
    };

    http
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers(
                            new AntPathRequestMatcher("/connect/**"),
                            new AntPathRequestMatcher("/actuator/**"),
                            new AntPathRequestMatcher("/login"),
                            new AntPathRequestMatcher("/login/**"),
                            new AntPathRequestMatcher("/login/context"),
                            new AntPathRequestMatcher("/assets/**"),
                            new AntPathRequestMatcher("/csrf"),
                            new AntPathRequestMatcher("/"),
                            new AntPathRequestMatcher("/favicon.ico"),
                            new AntPathRequestMatcher("/manifest*"),
                            new AntPathRequestMatcher("/robots.txt"),
                            new AntPathRequestMatcher("/.well-known/**"),
    new AntPathRequestMatcher("/__issuer")            // <-- add this line

                    ).permitAll()
                    .anyRequest().authenticated()
            )
            .formLogin(form -> form
                    .loginPage("/login")
                    .loginProcessingUrl("/login")
                    .successHandler((request, response, authentication) -> {
                      String target = savedHandler.determineTargetUrl(request, response);
                      if (target != null) {
                        Cookie del = new Cookie(CONT_COOKIE, ""); del.setPath("/"); del.setMaxAge(0); response.addCookie(del);
                        response.sendRedirect(target);
                        return;
                      }
                      response.setStatus(400);
                      response.setContentType("text/plain;charset=UTF-8");
                      response.getWriter().write("Login OK, but no original /oauth2/authorize request was found.");
                    })
                    .failureUrl("/login?error")
                    .permitAll()
            )
            .requestCache(c -> c.requestCache(authorizeOnlyRequestCache))
            .csrf(csrf -> csrf.disable())
            .cors(Customizer.withDefaults());

    return http.build();
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource(
          @Value("${CORS_ALLOWED_ORIGINS:*}") String originsProperty) {

    CorsConfiguration cfg = new CorsConfiguration();
    if ("*".equals(originsProperty.trim())) {
      cfg.setAllowedOrigins(List.of("*"));
      cfg.setAllowCredentials(false);
    } else {
      cfg.setAllowedOriginPatterns(List.of(originsProperty.split("\\s*,\\s*")));
      cfg.setAllowCredentials(true);
    }
    cfg.addAllowedMethod("*");
    cfg.addAllowedHeader("*");
    cfg.addExposedHeader("*");
    cfg.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
    src.registerCorsConfiguration("/**", cfg);
    return src;
  }

  // Keep a bean as well (harmless; the configurer call above already pins issuer)
  @Primary
  @Bean("authorizationServerSettings")
  AuthorizationServerSettings authorizationServerSettingsPrimary(
          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer) {
    log.info(">>> AuthorizationServerSettings bean issuer: {}", issuer);
    return AuthorizationServerSettings.builder().issuer(issuer).build();
  }

  @Bean JWKSource<SecurityContext> jwkSource(@Value("${auth.jwks.dir:./data/jwks}") String dir) {
    return new FileBackedJwks(dir);
  }
  @Bean RegisteredClientRepository registeredClientRepository(DataSource ds) {
    return new JdbcRegisteredClientRepository(new JdbcTemplate(ds));
  }
  @Bean OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
    return new JdbcOAuth2AuthorizationService(jdbc, repo);
  }
  @Bean OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
    return new JdbcOAuth2AuthorizationConsentService(jdbc, repo);
  }
  @Bean UserDetailsService users() {
    return new InMemoryUserDetailsManager(
            User.withUsername("user").password("{noop}password").roles("USER").build()
    );
  }

  private static boolean isAuthorizeUrl(String url) {
    try { return "/oauth2/authorize".equals(URI.create(url).getPath()); }
    catch (Exception e) { return false; }
  }
  private static String readCookie(HttpServletRequest req, String name) {
    Cookie[] cs = req.getCookies(); if (cs == null) return null;
    for (Cookie c : cs) if (name.equals(c.getName())) return c.getValue();
    return null;
  }
  private static boolean sameOrigin(String url, HttpServletRequest req) {
    try {
      URI u = URI.create(url);
      if (!u.isAbsolute()) return true;
      String host = req.getServerName();
      int port  = req.getServerPort();
      return host.equalsIgnoreCase(u.getHost()) && (u.getPort() == -1 || u.getPort() == port);
    } catch (Exception e) { return false; }
  }
}
