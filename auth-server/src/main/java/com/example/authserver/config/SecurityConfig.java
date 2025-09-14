////////////////////package com.example.authserver.config;
////////////////////
////////////////////import com.example.authserver.support.FileBackedJwks;
////////////////////import com.nimbusds.jose.jwk.source.JWKSource;
////////////////////import com.nimbusds.jose.proc.SecurityContext;
////////////////////import org.springframework.beans.factory.annotation.Value;
////////////////////import org.springframework.context.annotation.Bean;
////////////////////import org.springframework.context.annotation.Configuration;
////////////////////import org.springframework.core.Ordered;
////////////////////import org.springframework.core.annotation.Order;
////////////////////import org.springframework.jdbc.core.JdbcTemplate;
////////////////////import org.springframework.security.config.Customizer;
////////////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////////////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////////////////////import org.springframework.security.core.userdetails.User;
////////////////////import org.springframework.security.core.userdetails.UserDetailsService;
////////////////////import org.springframework.security.provisioning.InMemoryUserDetailsManager;
////////////////////import org.springframework.security.web.SecurityFilterChain;
////////////////////import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
////////////////////import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
////////////////////import org.springframework.security.web.util.matcher.RequestMatcher;
////////////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
////////////////////import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
////////////////////import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
////////////////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
////////////////////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
////////////////////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
////////////////////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
////////////////////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
////////////////////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
////////////////////import org.springframework.web.cors.CorsConfiguration;
////////////////////import org.springframework.web.cors.CorsConfigurationSource;
////////////////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
////////////////////
////////////////////import javax.sql.DataSource;
////////////////////import java.util.List;
////////////////////
////////////////////@Configuration
////////////////////@EnableWebSecurity
////////////////////public class SecurityConfig {
////////////////////
////////////////////  // ===== Authorization Server filter chain (do NOT override the entry point) =====
////////////////////  @Bean
////////////////////  @Order(Ordered.HIGHEST_PRECEDENCE)
////////////////////  SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
////////////////////    OAuth2AuthorizationServerConfigurer authz = new OAuth2AuthorizationServerConfigurer();
////////////////////    authz.oidc(Customizer.withDefaults());
////////////////////    RequestMatcher endpoints = authz.getEndpointsMatcher();
////////////////////
////////////////////    http.securityMatcher(endpoints)
////////////////////            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
////////////////////            .csrf(c -> c.ignoringRequestMatchers(endpoints))
////////////////////            .requestCache(c -> c.requestCache(new HttpSessionRequestCache()))
////////////////////            // Don't set a custom LoginUrlAuthenticationEntryPoint here;
////////////////////            // SAS will redirect to /login?continue=... automatically.
////////////////////            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
////////////////////            .cors(Customizer.withDefaults())
////////////////////            .apply(authz);
////////////////////
////////////////////    return http.build();
////////////////////  }
////////////////////
////////////////////  // ===== App (login UI, DCR, static) filter chain =====
////////////////////  @Bean
////////////////////  SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
////////////////////    http
////////////////////            .authorizeHttpRequests(auth -> auth
////////////////////                    .requestMatchers(
////////////////////                            new AntPathRequestMatcher("/connect/**"),
////////////////////                            new AntPathRequestMatcher("/actuator/**"),
////////////////////                            new AntPathRequestMatcher("/login"),
////////////////////                            new AntPathRequestMatcher("/login/**"),
////////////////////                            new AntPathRequestMatcher("/assets/**"),
////////////////////                            new AntPathRequestMatcher("/csrf"),
////////////////////                            new AntPathRequestMatcher("/")
////////////////////                    ).permitAll()
////////////////////                    .anyRequest().authenticated()
////////////////////            )
////////////////////            .formLogin(form -> form
////////////////////                    .loginPage("/login")
////////////////////                    .loginProcessingUrl("/login")
////////////////////                    // ✅ On success, prefer the SAS '?continue=' target if present
////////////////////                    .successHandler((request, response, authentication) -> {
////////////////////                      String cont = request.getParameter("continue");
////////////////////                      if (cont != null && !cont.isBlank()) {
////////////////////                        try {
////////////////////                          // Optional same-origin safety
////////////////////                          java.net.URI u = java.net.URI.create(cont);
////////////////////                          if (u.isAbsolute()) {
////////////////////                            String host = request.getServerName();
////////////////////                            int port = request.getServerPort();
////////////////////                            if (!host.equalsIgnoreCase(u.getHost()) || (u.getPort() != -1 && u.getPort() != port)) {
////////////////////                              new org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler()
////////////////////                                      .onAuthenticationSuccess(request, response, authentication);
////////////////////                              return;
////////////////////                            }
////////////////////                          }
////////////////////                          response.sendRedirect(cont);
////////////////////                          return;
////////////////////                        } catch (Exception ignored) {
////////////////////                        }
////////////////////                      }
////////////////////                      // Fallback to SavedRequest (or "/")
////////////////////                      new org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler()
////////////////////                              .onAuthenticationSuccess(request, response, authentication);
////////////////////                    })
////////////////////                    .failureUrl("/login?error")
////////////////////                    .permitAll()
////////////////////            )
////////////////////            .requestCache(c -> c.requestCache(new HttpSessionRequestCache()))
////////////////////            .csrf(csrf -> csrf
////////////////////                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////////////////////                    .ignoringRequestMatchers(new AntPathRequestMatcher("/connect/**"))
////////////////////            )
////////////////////            .cors(Customizer.withDefaults());
////////////////////
////////////////////    return http.build();
////////////////////  }
////////////////////
////////////////////  @Bean
////////////////////  CorsConfigurationSource corsConfigurationSource() {
////////////////////    CorsConfiguration cfg = new CorsConfiguration();
////////////////////    cfg.setAllowedOrigins(List.of("http://localhost:5174", "http://localhost:5173"));
////////////////////    cfg.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
////////////////////    cfg.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With", "X-CSRF-TOKEN"));
////////////////////    cfg.setAllowCredentials(true);
////////////////////    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
////////////////////    src.registerCorsConfiguration("/**", cfg);
////////////////////    return src;
////////////////////  }
////////////////////
////////////////////  @Bean
////////////////////  AuthorizationServerSettings authorizationServerSettings(
////////////////////          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer) {
////////////////////    return AuthorizationServerSettings.builder().issuer(issuer).build();
////////////////////  }
////////////////////
////////////////////  @Bean JWKSource<SecurityContext> jwkSource(@Value("${auth.jwks.dir:./data/jwks}") String dir) {
////////////////////    return new FileBackedJwks(dir);
////////////////////  }
////////////////////
////////////////////  @Bean RegisteredClientRepository registeredClientRepository(DataSource ds) {
////////////////////    return new JdbcRegisteredClientRepository(new JdbcTemplate(ds));
////////////////////  }
////////////////////
////////////////////  @Bean OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
////////////////////    return new JdbcOAuth2AuthorizationService(jdbc, repo);
////////////////////  }
////////////////////
////////////////////  @Bean OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
////////////////////    return new JdbcOAuth2AuthorizationConsentService(jdbc, repo);
////////////////////  }
////////////////////
////////////////////  @Bean
////////////////////  UserDetailsService users() {
////////////////////    return new InMemoryUserDetailsManager(
////////////////////            User.withUsername("user").password("{noop}password").roles("USER").build()
////////////////////    );
////////////////////  }
////////////////////}
//////////////////
//////////////////
//////////////////package com.example.authserver.config;
//////////////////
//////////////////import com.example.authserver.support.FileBackedJwks;
//////////////////import com.nimbusds.jose.jwk.source.JWKSource;
//////////////////import com.nimbusds.jose.proc.SecurityContext;
//////////////////import org.springframework.beans.factory.annotation.Value;
//////////////////import org.springframework.context.annotation.Bean;
//////////////////import org.springframework.context.annotation.Configuration;
//////////////////import org.springframework.core.Ordered;
//////////////////import org.springframework.core.annotation.Order;
//////////////////import org.springframework.jdbc.core.JdbcTemplate;
//////////////////import org.springframework.security.authentication.AnonymousAuthenticationToken;
//////////////////import org.springframework.security.config.Customizer;
//////////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//////////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//////////////////import org.springframework.security.core.Authentication;
//////////////////import org.springframework.security.core.context.SecurityContextHolder;
//////////////////import org.springframework.security.core.userdetails.User;
//////////////////import org.springframework.security.core.userdetails.UserDetailsService;
//////////////////import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//////////////////import org.springframework.security.web.SecurityFilterChain;
//////////////////import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//////////////////import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//////////////////import org.springframework.security.web.util.matcher.RequestMatcher;
//////////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//////////////////import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
//////////////////import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//////////////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//////////////////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
//////////////////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
//////////////////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
//////////////////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
//////////////////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
//////////////////import org.springframework.web.cors.CorsConfiguration;
//////////////////import org.springframework.web.cors.CorsConfigurationSource;
//////////////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//////////////////
//////////////////import javax.sql.DataSource;
//////////////////import jakarta.servlet.FilterChain;
//////////////////import jakarta.servlet.ServletException;
//////////////////import jakarta.servlet.http.HttpServletRequest;
//////////////////import jakarta.servlet.http.HttpServletResponse;
//////////////////import java.io.IOException;
//////////////////import java.util.List;
//////////////////
//////////////////@Configuration
//////////////////@EnableWebSecurity
//////////////////public class SecurityConfig {
//////////////////
//////////////////  /* ====== Authorization Server chain: DO NOT override entry point ====== */
//////////////////  @Bean
//////////////////  @Order(Ordered.HIGHEST_PRECEDENCE)
//////////////////  SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//////////////////    OAuth2AuthorizationServerConfigurer authz = new OAuth2AuthorizationServerConfigurer();
//////////////////    authz.oidc(Customizer.withDefaults());
//////////////////    RequestMatcher endpoints = authz.getEndpointsMatcher();
//////////////////
//////////////////    http.securityMatcher(endpoints)
//////////////////            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
//////////////////            .csrf(c -> c.ignoringRequestMatchers(endpoints))
//////////////////            .requestCache(c -> c.requestCache(new HttpSessionRequestCache()))
//////////////////            // don't add a custom authenticationEntryPoint here
//////////////////            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
//////////////////            .cors(Customizer.withDefaults())
//////////////////            .apply(authz);
//////////////////
//////////////////    return http.build();
//////////////////  }
//////////////////
//////////////////  /* ====== App chain (login UI, static, DCR) ====== */
//////////////////  @Bean
//////////////////  SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
//////////////////    http
//////////////////            .authorizeHttpRequests(auth -> auth
//////////////////                    .requestMatchers(
//////////////////                            new AntPathRequestMatcher("/connect/**"),
//////////////////                            new AntPathRequestMatcher("/actuator/**"),
//////////////////                            new AntPathRequestMatcher("/login"),
//////////////////                            new AntPathRequestMatcher("/login/**"),
//////////////////                            new AntPathRequestMatcher("/assets/**"),
//////////////////                            new AntPathRequestMatcher("/csrf"),
//////////////////                            new AntPathRequestMatcher("/error"),
//////////////////                            new AntPathRequestMatcher("/error/**"),
//////////////////                            new AntPathRequestMatcher("/")
//////////////////                    ).permitAll()
//////////////////                    .anyRequest().authenticated()
//////////////////            )
//////////////////            .formLogin(form -> form
//////////////////                    .loginPage("/login")
//////////////////                    .loginProcessingUrl("/login")
//////////////////                    .successHandler((request, response, authentication) -> {
//////////////////                      // Prefer SAS '?continue=' target if present
//////////////////                      String cont = request.getParameter("continue");
//////////////////                      if (cont != null && !cont.isBlank()) {
//////////////////                        try {
//////////////////                          java.net.URI u = java.net.URI.create(cont);
//////////////////                          // Optional same-origin guard
//////////////////                          if (u.isAbsolute()) {
//////////////////                            String host = request.getServerName();
//////////////////                            int port = request.getServerPort();
//////////////////                            if (!host.equalsIgnoreCase(u.getHost()) ||
//////////////////                                    (u.getPort() != -1 && u.getPort() != port)) {
//////////////////                              // fall back to saved request if host/port differ
//////////////////                              new org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler()
//////////////////                                      .onAuthenticationSuccess(request, response, authentication);
//////////////////                              return;
//////////////////                            }
//////////////////                          }
//////////////////                          response.sendRedirect(cont);
//////////////////                          return;
//////////////////                        } catch (Exception ignore) {
//////////////////                          // fall through
//////////////////                        }
//////////////////                      }
//////////////////                      // No continue: fall back to saved request or "/"
//////////////////                      new org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler()
//////////////////                              .onAuthenticationSuccess(request, response, authentication);
//////////////////                    })
//////////////////                    .failureUrl("/login?error")
//////////////////                    .permitAll()
//////////////////            )
//////////////////            .requestCache(c -> c.requestCache(new HttpSessionRequestCache()))
//////////////////            .csrf(csrf -> csrf
//////////////////                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//////////////////                    .ignoringRequestMatchers(new AntPathRequestMatcher("/connect/**"))
//////////////////            )
//////////////////            .cors(Customizer.withDefaults());
//////////////////
//////////////////    return http.build();
//////////////////  }
//////////////////
//////////////////  /* ====== Safety net: if /error?continue while authenticated, 302 back ====== */
//////////////////  @Bean
//////////////////  jakarta.servlet.Filter continueRedirectFilter() {
//////////////////    return new jakarta.servlet.Filter() {
//////////////////      @Override public void doFilter(
//////////////////              jakarta.servlet.ServletRequest req, jakarta.servlet.ServletResponse res, FilterChain chain)
//////////////////              throws IOException, ServletException {
//////////////////        HttpServletRequest request = (HttpServletRequest) req;
//////////////////        HttpServletResponse response = (HttpServletResponse) res;
//////////////////
//////////////////        if ("/error".equals(request.getRequestURI())) {
//////////////////          String cont = request.getParameter("continue");
//////////////////          Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//////////////////          boolean authed = (auth != null && auth.isAuthenticated()
//////////////////                  && !(auth instanceof AnonymousAuthenticationToken));
//////////////////          if (cont != null && !cont.isBlank() && authed) {
//////////////////            try {
//////////////////              java.net.URI u = java.net.URI.create(cont);
//////////////////              // optional same-origin guard
//////////////////              if (u.isAbsolute()) {
//////////////////                String host = request.getServerName();
//////////////////                int port = request.getServerPort();
//////////////////                if (!host.equalsIgnoreCase(u.getHost()) ||
//////////////////                        (u.getPort() != -1 && u.getPort() != port)) {
//////////////////                  // if not same-origin, just continue to default handler
//////////////////                  chain.doFilter(req, res);
//////////////////                  return;
//////////////////                }
//////////////////              }
//////////////////              response.setStatus(302);
//////////////////              response.setHeader("Location", cont);
//////////////////              return;
//////////////////            } catch (Exception ignored) {
//////////////////              // fall through
//////////////////            }
//////////////////          }
//////////////////        }
//////////////////        chain.doFilter(req, res);
//////////////////      }
//////////////////    };
//////////////////  }
//////////////////
//////////////////  /* ====== CORS, SAS infrastructure, demo users ====== */
//////////////////  @Bean
//////////////////  CorsConfigurationSource corsConfigurationSource() {
//////////////////    CorsConfiguration cfg = new CorsConfiguration();
//////////////////    cfg.setAllowedOrigins(List.of("http://localhost:5174", "http://localhost:5173"));
//////////////////    cfg.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
//////////////////    cfg.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With", "X-CSRF-TOKEN"));
//////////////////    cfg.setAllowCredentials(true);
//////////////////    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
//////////////////    src.registerCorsConfiguration("/**", cfg);
//////////////////    return src;
//////////////////  }
//////////////////
//////////////////  @Bean
//////////////////  AuthorizationServerSettings authorizationServerSettings(
//////////////////          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer) {
//////////////////    return AuthorizationServerSettings.builder().issuer(issuer).build();
//////////////////  }
//////////////////
//////////////////  @Bean JWKSource<SecurityContext> jwkSource(@Value("${auth.jwks.dir:./data/jwks}") String dir) {
//////////////////    return new FileBackedJwks(dir);
//////////////////  }
//////////////////
//////////////////  @Bean RegisteredClientRepository registeredClientRepository(DataSource ds) {
//////////////////    return new JdbcRegisteredClientRepository(new JdbcTemplate(ds));
//////////////////  }
//////////////////
//////////////////  @Bean OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
//////////////////    return new JdbcOAuth2AuthorizationService(jdbc, repo);
//////////////////  }
//////////////////
//////////////////  @Bean OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
//////////////////    return new JdbcOAuth2AuthorizationConsentService(jdbc, repo);
//////////////////  }
//////////////////
//////////////////  @Bean
//////////////////  UserDetailsService users() {
//////////////////    return new InMemoryUserDetailsManager(
//////////////////            User.withUsername("user").password("{noop}password").roles("USER").build()
//////////////////    );
//////////////////  }
//////////////////}
////////////////
////////////////package com.example.authserver.config;
////////////////
////////////////import com.example.authserver.support.FileBackedJwks;
////////////////import com.nimbusds.jose.jwk.source.JWKSource;
////////////////import com.nimbusds.jose.proc.SecurityContext;
////////////////import jakarta.servlet.FilterChain;
////////////////import jakarta.servlet.ServletException;
////////////////import jakarta.servlet.http.HttpServletRequest;
////////////////import jakarta.servlet.http.HttpServletResponse;
////////////////import org.springframework.beans.factory.annotation.Value;
////////////////import org.springframework.context.annotation.Bean;
////////////////import org.springframework.context.annotation.Configuration;
////////////////import org.springframework.core.Ordered;
////////////////import org.springframework.core.annotation.Order;
////////////////import org.springframework.jdbc.core.JdbcTemplate;
////////////////import org.springframework.security.authentication.AnonymousAuthenticationToken;
////////////////import org.springframework.security.config.Customizer;
////////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////////////////import org.springframework.security.core.Authentication;
////////////////import org.springframework.security.core.context.SecurityContextHolder;
////////////////import org.springframework.security.core.userdetails.User;
////////////////import org.springframework.security.core.userdetails.UserDetailsService;
////////////////import org.springframework.security.provisioning.InMemoryUserDetailsManager;
////////////////import org.springframework.security.web.SecurityFilterChain;
////////////////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
////////////////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
////////////////import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
////////////////import org.springframework.security.web.savedrequest.RequestCache;
////////////////import org.springframework.security.web.savedrequest.SavedRequest;
////////////////import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
////////////////import org.springframework.security.web.util.matcher.RequestMatcher;
////////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
////////////////import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
////////////////import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
////////////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
////////////////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
////////////////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
////////////////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
////////////////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
////////////////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
////////////////import org.springframework.web.cors.CorsConfiguration;
////////////////import org.springframework.web.cors.CorsConfigurationSource;
////////////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
////////////////import org.springframework.web.filter.OncePerRequestFilter;
////////////////
////////////////import javax.sql.DataSource;
////////////////import java.io.IOException;
////////////////import java.net.URI;
////////////////import java.util.List;
////////////////
////////////////@Configuration
////////////////@EnableWebSecurity
////////////////public class SecurityConfig {
////////////////
////////////////  private static final String CONTINUE_ATTR = "LOGIN_CONTINUE_URL";
////////////////
////////////////  // ===== Authorization Server chain (do NOT override its entry point) =====
////////////////  @Bean
////////////////  @Order(Ordered.HIGHEST_PRECEDENCE)
////////////////  SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
////////////////    OAuth2AuthorizationServerConfigurer authz = new OAuth2AuthorizationServerConfigurer();
////////////////    authz.oidc(Customizer.withDefaults());
////////////////    RequestMatcher endpoints = authz.getEndpointsMatcher();
////////////////
////////////////    http.securityMatcher(endpoints)
////////////////            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
////////////////            .csrf(c -> c.ignoringRequestMatchers(endpoints))
////////////////            .requestCache(c -> c.requestCache(new HttpSessionRequestCache()))
////////////////            // let SAS add /login?continue=...
////////////////            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
////////////////            .cors(Customizer.withDefaults())
////////////////            .apply(authz);
////////////////
////////////////    return http.build();
////////////////  }
////////////////
////////////////  // ===== App chain (login UI, static, DCR) =====
////////////////  @Bean
////////////////  SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
////////////////    http
////////////////            .authorizeHttpRequests(auth -> auth
////////////////                    .requestMatchers(
////////////////                            new AntPathRequestMatcher("/connect/**"),
////////////////                            new AntPathRequestMatcher("/actuator/**"),
////////////////                            new AntPathRequestMatcher("/login"),
////////////////                            new AntPathRequestMatcher("/login/**"),
////////////////                            new AntPathRequestMatcher("/assets/**"),
////////////////                            new AntPathRequestMatcher("/csrf"),
////////////////                            new AntPathRequestMatcher("/error"),
////////////////                            new AntPathRequestMatcher("/error/**"),
////////////////                            new AntPathRequestMatcher("/")
////////////////                    ).permitAll()
////////////////                    .anyRequest().authenticated()
////////////////            )
////////////////            // capture ?continue= on GET /login before the form is shown
////////////////            .addFilterBefore(loginContinueCaptureFilter(), UsernamePasswordAuthenticationFilter.class)
////////////////            .formLogin(form -> form
////////////////                    .loginPage("/login")
////////////////                    .loginProcessingUrl("/login")
////////////////                    .successHandler((request, response, authentication) -> {
////////////////                      // 1) try POST parameter
////////////////                      String cont = request.getParameter("continue");
////////////////
////////////////                      // 2) else try session copy captured at GET /login
////////////////                      if (cont == null || cont.isBlank()) {
////////////////                        Object v = request.getSession(false) != null ? request.getSession(false).getAttribute(CONTINUE_ATTR) : null;
////////////////                        if (v instanceof String s && !s.isBlank()) {
////////////////                          cont = s;
////////////////                        }
////////////////                      }
////////////////
////////////////                      // 3) else try SavedRequest from RequestCache
////////////////                      if (cont == null || cont.isBlank()) {
////////////////                        RequestCache cache = new HttpSessionRequestCache();
////////////////                        SavedRequest saved = cache.getRequest(request, response);
////////////////                        if (saved != null && saved.getRedirectUrl() != null) {
////////////////                          cont = saved.getRedirectUrl();
////////////////                        }
////////////////                      }
////////////////
////////////////                      // if we found a target, validate same-origin then redirect
////////////////                      if (cont != null && !cont.isBlank()) {
////////////////                        try {
////////////////                          URI u = URI.create(cont);
////////////////                          if (u.isAbsolute()) {
////////////////                            String host = request.getServerName();
////////////////                            int port = request.getServerPort();
////////////////                            if (!host.equalsIgnoreCase(u.getHost()) ||
////////////////                                    (u.getPort() != -1 && u.getPort() != port)) {
////////////////                              // not same-origin: fall back to saved request handler
////////////////                              new SavedRequestAwareAuthenticationSuccessHandler()
////////////////                                      .onAuthenticationSuccess(request, response, authentication);
////////////////                              return;
////////////////                            }
////////////////                          }
////////////////                          // clear the session hint before redirecting
////////////////                          if (request.getSession(false) != null) {
////////////////                            request.getSession(false).removeAttribute(CONTINUE_ATTR);
////////////////                          }
////////////////                          response.sendRedirect(cont);
////////////////                          return;
////////////////                        } catch (Exception ignored) { /* fall through */ }
////////////////                      }
////////////////
////////////////                      // 4) fallback: saved-request handler (will use "/" if none)
////////////////                      new SavedRequestAwareAuthenticationSuccessHandler()
////////////////                              .onAuthenticationSuccess(request, response, authentication);
////////////////                    })
////////////////                    .failureUrl("/login?error")
////////////////                    .permitAll()
////////////////            )
////////////////            .requestCache(c -> c.requestCache(new HttpSessionRequestCache()))
////////////////            .csrf(csrf -> csrf
////////////////                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////////////////                    .ignoringRequestMatchers(new AntPathRequestMatcher("/connect/**"))
////////////////            )
////////////////            .cors(Customizer.withDefaults());
////////////////
////////////////    return http.build();
////////////////  }
////////////////
////////////////  // GET /login -> stash ?continue= in session for robust handoff on POST
////////////////  @Bean
////////////////  OncePerRequestFilter loginContinueCaptureFilter() {
////////////////    return new OncePerRequestFilter() {
////////////////      @Override
////////////////      protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
////////////////              throws ServletException, IOException {
////////////////        if ("GET".equalsIgnoreCase(request.getMethod())
////////////////                && "/login".equals(request.getRequestURI())) {
////////////////          String cont = request.getParameter("continue");
////////////////          if (cont != null && !cont.isBlank()) {
////////////////            request.getSession(true).setAttribute(CONTINUE_ATTR, cont);
////////////////          }
////////////////        }
////////////////        chain.doFilter(request, response);
////////////////      }
////////////////    };
////////////////  }
////////////////
////////////////  // Safety net: if we ever hit /error?continue while already authenticated, 302 back
////////////////  @Bean
////////////////  jakarta.servlet.Filter continueRedirectFilter() {
////////////////    return (req, res, chain) -> {
////////////////      HttpServletRequest request = (HttpServletRequest) req;
////////////////      HttpServletResponse response = (HttpServletResponse) res;
////////////////
////////////////      if ("/error".equals(request.getRequestURI())) {
////////////////        String cont = request.getParameter("continue");
////////////////        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
////////////////        boolean authed = (auth != null && auth.isAuthenticated()
////////////////                && !(auth instanceof AnonymousAuthenticationToken));
////////////////        if (cont != null && !cont.isBlank() && authed) {
////////////////          try {
////////////////            URI u = URI.create(cont);
////////////////            if (u.isAbsolute()) {
////////////////              String host = request.getServerName();
////////////////              int port = request.getServerPort();
////////////////              if (!host.equalsIgnoreCase(u.getHost()) ||
////////////////                      (u.getPort() != -1 && u.getPort() != port)) {
////////////////                chain.doFilter(req, res);
////////////////                return;
////////////////              }
////////////////            }
////////////////            response.setStatus(302);
////////////////            response.setHeader("Location", cont);
////////////////            return;
////////////////          } catch (Exception ignored) { }
////////////////        }
////////////////      }
////////////////      chain.doFilter(req, res);
////////////////    };
////////////////  }
////////////////
////////////////  @Bean
////////////////  CorsConfigurationSource corsConfigurationSource() {
////////////////    CorsConfiguration cfg = new CorsConfiguration();
////////////////    cfg.setAllowedOrigins(List.of("http://localhost:5174", "http://localhost:5173"));
////////////////    cfg.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
////////////////    cfg.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With", "X-CSRF-TOKEN"));
////////////////    cfg.setAllowCredentials(true);
////////////////    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
////////////////    src.registerCorsConfiguration("/**", cfg);
////////////////    return src;
////////////////  }
////////////////
////////////////  @Bean
////////////////  AuthorizationServerSettings authorizationServerSettings(
////////////////          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer) {
////////////////    return AuthorizationServerSettings.builder().issuer(issuer).build();
////////////////  }
////////////////
////////////////  @Bean JWKSource<SecurityContext> jwkSource(@Value("${auth.jwks.dir:./data/jwks}") String dir) {
////////////////    return new FileBackedJwks(dir);
////////////////  }
////////////////
////////////////  @Bean RegisteredClientRepository registeredClientRepository(DataSource ds) {
////////////////    return new JdbcRegisteredClientRepository(new JdbcTemplate(ds));
////////////////  }
////////////////
////////////////  @Bean OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
////////////////    return new JdbcOAuth2AuthorizationService(jdbc, repo);
////////////////  }
////////////////
////////////////  @Bean OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
////////////////    return new JdbcOAuth2AuthorizationConsentService(jdbc, repo);
////////////////  }
////////////////
////////////////  @Bean
////////////////  UserDetailsService users() {
////////////////    return new InMemoryUserDetailsManager(
////////////////            User.withUsername("user").password("{noop}password").roles("USER").build()
////////////////    );
////////////////  }
////////////////}
//////////////
//////////////
//////////////package com.example.authserver.config;
//////////////
//////////////import com.example.authserver.support.FileBackedJwks;
//////////////import com.nimbusds.jose.jwk.source.JWKSource;
//////////////import com.nimbusds.jose.proc.SecurityContext;
//////////////import jakarta.servlet.FilterChain;
//////////////import jakarta.servlet.ServletException;
//////////////import jakarta.servlet.http.HttpServletRequest;
//////////////import jakarta.servlet.http.HttpServletResponse;
//////////////import org.springframework.beans.factory.annotation.Value;
//////////////import org.springframework.context.annotation.Bean;
//////////////import org.springframework.context.annotation.Configuration;
//////////////import org.springframework.core.Ordered;
//////////////import org.springframework.core.annotation.Order;
//////////////import org.springframework.jdbc.core.JdbcTemplate;
//////////////import org.springframework.security.authentication.AnonymousAuthenticationToken;
//////////////import org.springframework.security.config.Customizer;
//////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//////////////import org.springframework.security.core.Authentication;
//////////////import org.springframework.security.core.context.SecurityContextHolder;
//////////////import org.springframework.security.core.userdetails.User;
//////////////import org.springframework.security.core.userdetails.UserDetailsService;
//////////////import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//////////////import org.springframework.security.web.SecurityFilterChain;
//////////////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
//////////////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//////////////import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//////////////import org.springframework.security.web.savedrequest.RequestCache;
//////////////import org.springframework.security.web.savedrequest.SavedRequest;
//////////////import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//////////////import org.springframework.security.web.util.matcher.RequestMatcher;
//////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//////////////import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
//////////////import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//////////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//////////////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
//////////////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
//////////////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
//////////////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
//////////////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
//////////////import org.springframework.web.cors.CorsConfiguration;
//////////////import org.springframework.web.cors.CorsConfigurationSource;
//////////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//////////////import org.springframework.web.filter.OncePerRequestFilter;
//////////////
//////////////import javax.sql.DataSource;
//////////////import java.io.IOException;
//////////////import java.net.URI;
//////////////import java.util.List;
//////////////
//////////////@Configuration
//////////////@EnableWebSecurity
//////////////public class SecurityConfig {
//////////////
//////////////  private static final String CONTINUE_ATTR = "LOGIN_CONTINUE_URL";
//////////////
//////////////  /* ===== Authorization Server chain (leave entry point to SAS) ===== */
//////////////  @Bean
//////////////  @Order(Ordered.HIGHEST_PRECEDENCE)
//////////////  SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//////////////    var authz = new OAuth2AuthorizationServerConfigurer();
//////////////    authz.oidc(Customizer.withDefaults());
//////////////    RequestMatcher endpoints = authz.getEndpointsMatcher();
//////////////
//////////////    http.securityMatcher(endpoints)
//////////////            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
//////////////            .csrf(c -> c.ignoringRequestMatchers(endpoints))
//////////////            .requestCache(c -> c.requestCache(new HttpSessionRequestCache()))
//////////////            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
//////////////            .cors(Customizer.withDefaults())
//////////////            .apply(authz);
//////////////
//////////////    return http.build();
//////////////  }
//////////////
//////////////  /* ===== App chain (login UI, static, DCR) ===== */
//////////////  @Bean
//////////////  SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
//////////////    http
//////////////            .authorizeHttpRequests(auth -> auth
//////////////                    .requestMatchers(
//////////////                            new AntPathRequestMatcher("/connect/**"),
//////////////                            new AntPathRequestMatcher("/actuator/**"),
//////////////                            new AntPathRequestMatcher("/login"),
//////////////                            new AntPathRequestMatcher("/login/**"),
//////////////                            new AntPathRequestMatcher("/assets/**"),
//////////////                            new AntPathRequestMatcher("/csrf"),
//////////////                            new AntPathRequestMatcher("/error"),
//////////////                            new AntPathRequestMatcher("/error/**"),
//////////////                            new AntPathRequestMatcher("/")
//////////////                    ).permitAll()
//////////////                    .anyRequest().authenticated()
//////////////            )
//////////////            // Capture ?continue= on ANY /login* GET (handles /login, /login/, /login/index.html)
//////////////            .addFilterBefore(loginContinueCaptureFilter(), UsernamePasswordAuthenticationFilter.class)
//////////////            .formLogin(form -> form
//////////////                    .loginPage("/login")
//////////////                    .loginProcessingUrl("/login")
//////////////                    .successHandler((request, response, authentication) -> {
//////////////                      // 1) Prefer the SavedRequest (SAS saved /oauth2/authorize here)
//////////////                      RequestCache cache = new HttpSessionRequestCache();
//////////////                      SavedRequest saved = cache.getRequest(request, response);
//////////////                      if (saved != null && saved.getRedirectUrl() != null) {
//////////////                        response.sendRedirect(saved.getRedirectUrl());
//////////////                        return;
//////////////                      }
//////////////
//////////////                      // 2) Try POST body ?continue=
//////////////                      String cont = request.getParameter("continue");
//////////////
//////////////                      // 3) Fallback to session copy captured at GET /login
//////////////                      if (cont == null || cont.isBlank()) {
//////////////                        var ses = request.getSession(false);
//////////////                        Object v = ses != null ? ses.getAttribute(CONTINUE_ATTR) : null;
//////////////                        if (v instanceof String s && !s.isBlank()) cont = s;
//////////////                      }
//////////////
//////////////                      if (cont != null && !cont.isBlank()) {
//////////////                        try {
//////////////                          URI u = URI.create(cont);
//////////////                          // same-origin guard
//////////////                          if (u.isAbsolute()) {
//////////////                            String host = request.getServerName();
//////////////                            int port = request.getServerPort();
//////////////                            if (!host.equalsIgnoreCase(u.getHost()) ||
//////////////                                    (u.getPort() != -1 && u.getPort() != port)) {
//////////////                              // not same-origin -> fall back
//////////////                              new SavedRequestAwareAuthenticationSuccessHandler()
//////////////                                      .onAuthenticationSuccess(request, response, authentication);
//////////////                              return;
//////////////                            }
//////////////                          }
//////////////                          var ses = request.getSession(false);
//////////////                          if (ses != null) ses.removeAttribute(CONTINUE_ATTR);
//////////////                          response.sendRedirect(cont);
//////////////                          return;
//////////////                        } catch (Exception ignored) {}
//////////////                      }
//////////////
//////////////                      // 4) Ultimate fallback ("/" if nothing saved)
//////////////                      new SavedRequestAwareAuthenticationSuccessHandler()
//////////////                              .onAuthenticationSuccess(request, response, authentication);
//////////////                    })
//////////////                    .failureUrl("/login?error")
//////////////                    .permitAll()
//////////////            )
//////////////            .requestCache(c -> c.requestCache(new HttpSessionRequestCache()))
//////////////            .csrf(csrf -> csrf
//////////////                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//////////////                    .ignoringRequestMatchers(new AntPathRequestMatcher("/connect/**"))
//////////////            )
//////////////            .cors(Customizer.withDefaults());
//////////////
//////////////    return http.build();
//////////////  }
//////////////
//////////////  /* GET /login* — stash ?continue= in session early */
//////////////  @Bean
//////////////  OncePerRequestFilter loginContinueCaptureFilter() {
//////////////    return new OncePerRequestFilter() {
//////////////      @Override
//////////////      protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
//////////////              throws ServletException, IOException {
//////////////        if ("GET".equalsIgnoreCase(request.getMethod())) {
//////////////          String path = request.getRequestURI();
//////////////          if (path != null && path.startsWith("/login")) {
//////////////            String cont = request.getParameter("continue");
//////////////            if (cont != null && !cont.isBlank()) {
//////////////              request.getSession(true).setAttribute(CONTINUE_ATTR, cont);
//////////////            }
//////////////          }
//////////////        }
//////////////        chain.doFilter(request, response);
//////////////      }
//////////////    };
//////////////  }
//////////////
//////////////  /* Safety net: /error?continue while authenticated -> bounce back */
//////////////  @Bean
//////////////  jakarta.servlet.Filter continueRedirectFilter() {
//////////////    return (req, res, chain) -> {
//////////////      HttpServletRequest request = (HttpServletRequest) req;
//////////////      HttpServletResponse response = (HttpServletResponse) res;
//////////////
//////////////      if ("/error".equals(request.getRequestURI())) {
//////////////        String cont = request.getParameter("continue");
//////////////        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//////////////        boolean authed = (auth != null && auth.isAuthenticated()
//////////////                && !(auth instanceof AnonymousAuthenticationToken));
//////////////        if (cont != null && !cont.isBlank() && authed) {
//////////////          try {
//////////////            URI u = URI.create(cont);
//////////////            if (u.isAbsolute()) {
//////////////              String host = request.getServerName();
//////////////              int port = request.getServerPort();
//////////////              if (!host.equalsIgnoreCase(u.getHost()) ||
//////////////                      (u.getPort() != -1 && u.getPort() != port)) {
//////////////                chain.doFilter(req, res);
//////////////                return;
//////////////              }
//////////////            }
//////////////            response.setStatus(302);
//////////////            response.setHeader("Location", cont);
//////////////            return;
//////////////          } catch (Exception ignored) { }
//////////////        }
//////////////      }
//////////////      chain.doFilter(req, res);
//////////////    };
//////////////  }
//////////////
//////////////  @Bean
//////////////  CorsConfigurationSource corsConfigurationSource() {
//////////////    CorsConfiguration cfg = new CorsConfiguration();
//////////////    cfg.setAllowedOrigins(List.of("http://localhost:5174", "http://localhost:5173"));
//////////////    cfg.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
//////////////    cfg.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With", "X-CSRF-TOKEN"));
//////////////    cfg.setAllowCredentials(true);
//////////////    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
//////////////    src.registerCorsConfiguration("/**", cfg);
//////////////    return src;
//////////////  }
//////////////
//////////////  @Bean
//////////////  AuthorizationServerSettings authorizationServerSettings(
//////////////          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer) {
//////////////    return AuthorizationServerSettings.builder().issuer(issuer).build();
//////////////  }
//////////////
//////////////  @Bean JWKSource<SecurityContext> jwkSource(@Value("${auth.jwks.dir:./data/jwks}") String dir) {
//////////////    return new FileBackedJwks(dir);
//////////////  }
//////////////
//////////////  @Bean RegisteredClientRepository registeredClientRepository(DataSource ds) {
//////////////    return new JdbcRegisteredClientRepository(new JdbcTemplate(ds));
//////////////  }
//////////////
//////////////  @Bean OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
//////////////    return new JdbcOAuth2AuthorizationService(jdbc, repo);
//////////////  }
//////////////
//////////////  @Bean OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
//////////////    return new JdbcOAuth2AuthorizationConsentService(jdbc, repo);
//////////////  }
//////////////
//////////////  @Bean
//////////////  UserDetailsService users() {
//////////////    return new InMemoryUserDetailsManager(
//////////////            User.withUsername("user").password("{noop}password").roles("USER").build()
//////////////    );
//////////////  }
//////////////}
////////////
////////////
////////////package com.example.authserver.config;
////////////
////////////import com.example.authserver.support.FileBackedJwks;
////////////import com.nimbusds.jose.jwk.source.JWKSource;
////////////import com.nimbusds.jose.proc.SecurityContext;
////////////import jakarta.servlet.FilterChain;
////////////import jakarta.servlet.ServletException;
////////////import jakarta.servlet.http.HttpServletRequest;
////////////import jakarta.servlet.http.HttpServletResponse;
////////////import org.springframework.beans.factory.annotation.Value;
////////////import org.springframework.context.annotation.Bean;
////////////import org.springframework.context.annotation.Configuration;
////////////import org.springframework.core.Ordered;
////////////import org.springframework.core.annotation.Order;
////////////import org.springframework.jdbc.core.JdbcTemplate;
////////////import org.springframework.security.authentication.AnonymousAuthenticationToken;
////////////import org.springframework.security.config.Customizer;
////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////////////import org.springframework.security.core.Authentication;
////////////import org.springframework.security.core.context.SecurityContextHolder;
////////////import org.springframework.security.core.userdetails.User;
////////////import org.springframework.security.core.userdetails.UserDetailsService;
////////////import org.springframework.security.provisioning.InMemoryUserDetailsManager;
////////////import org.springframework.security.web.SecurityFilterChain;
////////////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
////////////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
////////////import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
////////////import org.springframework.security.web.savedrequest.RequestCache;
////////////import org.springframework.security.web.savedrequest.SavedRequest;
////////////import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
////////////import org.springframework.security.web.util.matcher.RequestMatcher;
////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
////////////import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
////////////import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
////////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
////////////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
////////////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
////////////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
////////////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
////////////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
////////////import org.springframework.web.cors.CorsConfiguration;
////////////import org.springframework.web.cors.CorsConfigurationSource;
////////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
////////////import org.springframework.web.filter.OncePerRequestFilter;
////////////
////////////import javax.sql.DataSource;
////////////import java.io.IOException;
////////////import java.net.URI;
////////////import java.util.List;
////////////
////////////@Configuration
////////////@EnableWebSecurity
////////////public class SecurityConfig {
////////////
////////////  private static final String CONTINUE_ATTR = "LOGIN_CONTINUE_URL";
////////////
////////////  // ===== Authorization Server chain (leave entry point to SAS) =====
////////////  @Bean
////////////  @Order(Ordered.HIGHEST_PRECEDENCE)
////////////  SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
////////////    var authz = new OAuth2AuthorizationServerConfigurer();
////////////    authz.oidc(Customizer.withDefaults());
////////////    RequestMatcher endpoints = authz.getEndpointsMatcher();
////////////
////////////    http.securityMatcher(endpoints)
////////////            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
////////////            .csrf(c -> c.ignoringRequestMatchers(endpoints))
////////////            .requestCache(c -> c.requestCache(new HttpSessionRequestCache()))
////////////            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
////////////            .cors(Customizer.withDefaults())
////////////            .apply(authz);
////////////
////////////    return http.build();
////////////  }
////////////
////////////  // ===== App chain (login UI, static, DCR) =====
////////////  @Bean
////////////  SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
////////////    http
////////////            .authorizeHttpRequests(auth -> auth
////////////                    .requestMatchers(
////////////                            new AntPathRequestMatcher("/connect/**"),
////////////                            new AntPathRequestMatcher("/actuator/**"),
////////////                            new AntPathRequestMatcher("/login"),
////////////                            new AntPathRequestMatcher("/login/**"),
////////////                            new AntPathRequestMatcher("/assets/**"),
////////////                            new AntPathRequestMatcher("/csrf"),
////////////                            new AntPathRequestMatcher("/error"),
////////////                            new AntPathRequestMatcher("/error/**"),
////////////                            new AntPathRequestMatcher("/")
////////////                    ).permitAll()
////////////                    .anyRequest().authenticated()
////////////            )
////////////            // capture ?continue= on ANY /login* GET (handles /login, /login/, /login/index.html)
////////////            .addFilterBefore(loginContinueCaptureFilter(), UsernamePasswordAuthenticationFilter.class)
////////////            .formLogin(form -> form
////////////                    .loginPage("/login")
////////////                    .loginProcessingUrl("/login")
////////////                    .successHandler((request, response, authentication) -> {
////////////                      // Priority 1: session-captured continue (most reliable)
////////////                      String cont = null;
////////////                      var ses = request.getSession(false);
////////////                      if (ses != null) {
////////////                        Object v = ses.getAttribute(CONTINUE_ATTR);
////////////                        if (v instanceof String s && !s.isBlank()) cont = s;
////////////                      }
////////////
////////////                      // Priority 2: POST body ?continue=
////////////                      if (cont == null || cont.isBlank()) {
////////////                        String bodyCont = request.getParameter("continue");
////////////                        if (bodyCont != null && !bodyCont.isBlank()) cont = bodyCont;
////////////                      }
////////////
////////////                      // Priority 3: SavedRequest from RequestCache (SAS stored /oauth2/authorize)
////////////                      if (cont == null || cont.isBlank()) {
////////////                        RequestCache cache = new HttpSessionRequestCache();
////////////                        SavedRequest saved = cache.getRequest(request, response);
////////////                        if (saved != null && saved.getRedirectUrl() != null) cont = saved.getRedirectUrl();
////////////                      }
////////////
////////////                      if (cont != null && !cont.isBlank()) {
////////////                        try {
////////////                          URI u = URI.create(cont);
////////////                          // same-origin safety
////////////                          if (u.isAbsolute()) {
////////////                            String host = request.getServerName();
////////////                            int port = request.getServerPort();
////////////                            if (!host.equalsIgnoreCase(u.getHost()) ||
////////////                                    (u.getPort() != -1 && u.getPort() != port)) {
////////////                              // different origin -> fallback to saved-request handler
////////////                              new SavedRequestAwareAuthenticationSuccessHandler()
////////////                                      .onAuthenticationSuccess(request, response, authentication);
////////////                              return;
////////////                            }
////////////                          }
////////////                          if (ses != null) ses.removeAttribute(CONTINUE_ATTR);
////////////                          response.sendRedirect(cont); // resumes /oauth2/authorize -> 302 to SPA /oidc/callback
////////////                          return;
////////////                        } catch (Exception ignored) {}
////////////                      }
////////////
////////////                      // Fallback: default success behavior ("/")
////////////                      new SavedRequestAwareAuthenticationSuccessHandler()
////////////                              .onAuthenticationSuccess(request, response, authentication);
////////////                    })
////////////                    .failureUrl("/login?error")
////////////                    .permitAll()
////////////            )
////////////            .requestCache(c -> c.requestCache(new HttpSessionRequestCache()))
////////////            .csrf(csrf -> csrf
////////////                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////////////                    .ignoringRequestMatchers(new AntPathRequestMatcher("/connect/**"))
////////////            )
////////////            .cors(Customizer.withDefaults());
////////////
////////////    return http.build();
////////////  }
////////////
////////////  // GET /login* — stash ?continue= in session early
////////////  @Bean
////////////  OncePerRequestFilter loginContinueCaptureFilter() {
////////////    return new OncePerRequestFilter() {
////////////      @Override
////////////      protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
////////////              throws ServletException, IOException {
////////////        if ("GET".equalsIgnoreCase(request.getMethod())) {
////////////          String path = request.getRequestURI();
////////////          if (path != null && path.startsWith("/login")) {
////////////            String cont = request.getParameter("continue");
////////////            if (cont != null && !cont.isBlank()) {
////////////              request.getSession(true).setAttribute(CONTINUE_ATTR, cont);
////////////            }
////////////          }
////////////        }
////////////        chain.doFilter(request, response);
////////////      }
////////////    };
////////////  }
////////////
////////////  // Safety net: /error?continue while authenticated -> bounce back
////////////  @Bean
////////////  jakarta.servlet.Filter continueRedirectFilter() {
////////////    return (req, res, chain) -> {
////////////      HttpServletRequest request = (HttpServletRequest) req;
////////////      HttpServletResponse response = (HttpServletResponse) res;
////////////
////////////      if ("/error".equals(request.getRequestURI())) {
////////////        String cont = request.getParameter("continue");
////////////        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
////////////        boolean authed = (auth != null && auth.isAuthenticated()
////////////                && !(auth instanceof AnonymousAuthenticationToken));
////////////        if (cont != null && !cont.isBlank() && authed) {
////////////          try {
////////////            URI u = URI.create(cont);
////////////            if (u.isAbsolute()) {
////////////              String host = request.getServerName();
////////////              int port = request.getServerPort();
////////////              if (!host.equalsIgnoreCase(u.getHost()) ||
////////////                      (u.getPort() != -1 && u.getPort() != port)) {
////////////                chain.doFilter(req, res);
////////////                return;
////////////              }
////////////            }
////////////            response.setStatus(302);
////////////            response.setHeader("Location", cont);
////////////            return;
////////////          } catch (Exception ignored) { }
////////////        }
////////////      }
////////////      chain.doFilter(req, res);
////////////    };
////////////  }
////////////
////////////  @Bean
////////////  CorsConfigurationSource corsConfigurationSource() {
////////////    CorsConfiguration cfg = new CorsConfiguration();
////////////    cfg.setAllowedOrigins(List.of("http://localhost:5174", "http://localhost:5173"));
////////////    cfg.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
////////////    cfg.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With", "X-CSRF-TOKEN"));
////////////    cfg.setAllowCredentials(true);
////////////    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
////////////    src.registerCorsConfiguration("/**", cfg);
////////////    return src;
////////////  }
////////////
////////////  @Bean
////////////  AuthorizationServerSettings authorizationServerSettings(
////////////          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer) {
////////////    return AuthorizationServerSettings.builder().issuer(issuer).build();
////////////  }
////////////
////////////  @Bean JWKSource<SecurityContext> jwkSource(@Value("${auth.jwks.dir:./data/jwks}") String dir) {
////////////    return new FileBackedJwks(dir);
////////////  }
////////////
////////////  @Bean RegisteredClientRepository registeredClientRepository(DataSource ds) {
////////////    return new JdbcRegisteredClientRepository(new JdbcTemplate(ds));
////////////  }
////////////
////////////  @Bean OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
////////////    return new JdbcOAuth2AuthorizationService(jdbc, repo);
////////////  }
////////////
////////////  @Bean OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
////////////    return new JdbcOAuth2AuthorizationConsentService(jdbc, repo);
////////////  }
////////////
////////////  @Bean
////////////  UserDetailsService users() {
////////////    return new InMemoryUserDetailsManager(
////////////            User.withUsername("user").password("{noop}password").roles("USER").build()
////////////    );
////////////  }
////////////}
//////////
//////////package com.example.authserver.config;
//////////
//////////import com.example.authserver.support.FileBackedJwks;
//////////import com.nimbusds.jose.jwk.source.JWKSource;
//////////import com.nimbusds.jose.proc.SecurityContext;
//////////import org.springframework.beans.factory.annotation.Value;
//////////import org.springframework.context.annotation.Bean;
//////////import org.springframework.context.annotation.Configuration;
//////////import org.springframework.core.Ordered;
//////////import org.springframework.core.annotation.Order;
//////////import org.springframework.jdbc.core.JdbcTemplate;
//////////import org.springframework.security.config.Customizer;
//////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//////////import org.springframework.security.core.userdetails.User;
//////////import org.springframework.security.core.userdetails.UserDetailsService;
//////////import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//////////import org.springframework.security.web.SecurityFilterChain;
//////////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
//////////import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//////////import org.springframework.security.web.savedrequest.RequestCache;
//////////import org.springframework.security.web.savedrequest.SavedRequest;
//////////import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//////////import org.springframework.security.web.util.matcher.RequestMatcher;
//////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//////////import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
//////////import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//////////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
//////////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
//////////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
//////////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
//////////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
//////////import org.springframework.web.cors.CorsConfiguration;
//////////import org.springframework.web.cors.CorsConfigurationSource;
//////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//////////
//////////import javax.sql.DataSource;
//////////import java.net.URI;
//////////import java.util.List;
//////////
//////////@Configuration
//////////@EnableWebSecurity
//////////public class SecurityConfig {
//////////
//////////  // ==================== Authorization Server chain ====================
//////////  @Bean
//////////  @Order(Ordered.HIGHEST_PRECEDENCE)
//////////  SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//////////    var authz = new OAuth2AuthorizationServerConfigurer();
//////////    authz.oidc(Customizer.withDefaults());
//////////    RequestMatcher endpoints = authz.getEndpointsMatcher();
//////////
//////////    http.securityMatcher(endpoints)
//////////            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
//////////            .csrf(c -> c.ignoringRequestMatchers(endpoints))
//////////            .requestCache(c -> c.requestCache(new HttpSessionRequestCache()))
//////////            // Let SAS redirect to /login?continue=... automatically
//////////            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
//////////            .cors(Customizer.withDefaults())
//////////            .apply(authz);
//////////
//////////    return http.build();
//////////  }
//////////
//////////  // ==================== Application chain (login UI, static, DCR) ====================
//////////  @Bean
//////////  SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
//////////    http
//////////            .authorizeHttpRequests(auth -> auth
//////////                    .requestMatchers(
//////////                            new AntPathRequestMatcher("/connect/**"),
//////////                            new AntPathRequestMatcher("/actuator/**"),
//////////                            new AntPathRequestMatcher("/login"),
//////////                            new AntPathRequestMatcher("/login/**"),
//////////                            new AntPathRequestMatcher("/assets/**"),
//////////                            new AntPathRequestMatcher("/csrf"),
//////////                            new AntPathRequestMatcher("/"),
//////////                            new AntPathRequestMatcher("/error"),
//////////                            new AntPathRequestMatcher("/error/**")
//////////                    ).permitAll()
//////////                    .anyRequest().authenticated()
//////////            )
//////////            .formLogin(form -> form
//////////                    .loginPage("/login")
//////////                    .loginProcessingUrl("/login")
//////////                    .successHandler((request, response, authentication) -> {
//////////                      // 1) Prefer the SavedRequest (original /oauth2/authorize?... saved by SAS)
//////////                      RequestCache cache = new HttpSessionRequestCache();
//////////                      SavedRequest saved = cache.getRequest(request, response);
//////////                      if (saved != null && saved.getRedirectUrl() != null) {
//////////                        response.sendRedirect(saved.getRedirectUrl());
//////////                        return;
//////////                      }
//////////
//////////                      // 2) Fallback to posted ?continue= (if present)
//////////                      String cont = request.getParameter("continue");
//////////                      if (cont != null && !cont.isBlank()) {
//////////                        try {
//////////                          URI u = URI.create(cont);
//////////                          // simple same-origin guard
//////////                          if (u.isAbsolute()) {
//////////                            String host = request.getServerName();
//////////                            int port = request.getServerPort();
//////////                            if (!host.equalsIgnoreCase(u.getHost()) || (u.getPort() != -1 && u.getPort() != port)) {
//////////                              new SavedRequestAwareAuthenticationSuccessHandler()
//////////                                      .onAuthenticationSuccess(request, response, authentication);
//////////                              return;
//////////                            }
//////////                          }
//////////                          response.sendRedirect(cont);
//////////                          return;
//////////                        } catch (Exception ignore) {}
//////////                      }
//////////
//////////                      // 3) Last resort: default saved-request handler (lands on "/")
//////////                      new SavedRequestAwareAuthenticationSuccessHandler()
//////////                              .onAuthenticationSuccess(request, response, authentication);
//////////                    })
//////////                    .failureUrl("/login?error")
//////////                    .permitAll()
//////////            )
//////////            .requestCache(c -> c.requestCache(new HttpSessionRequestCache()))
//////////            .csrf(csrf -> csrf
//////////                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//////////                    .ignoringRequestMatchers(new AntPathRequestMatcher("/connect/**"))
//////////            )
//////////            .cors(Customizer.withDefaults());
//////////
//////////    return http.build();
//////////  }
//////////
//////////  // ==================== CORS & infrastructure beans ====================
//////////  @Bean
//////////  CorsConfigurationSource corsConfigurationSource() {
//////////    CorsConfiguration cfg = new CorsConfiguration();
//////////    cfg.setAllowedOrigins(List.of("http://localhost:5174", "http://localhost:5173"));
//////////    cfg.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
//////////    cfg.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With", "X-CSRF-TOKEN"));
//////////    cfg.setAllowCredentials(true);
//////////    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
//////////    src.registerCorsConfiguration("/**", cfg);
//////////    return src;
//////////  }
//////////
//////////  @Bean
//////////  AuthorizationServerSettings authorizationServerSettings(
//////////          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer) {
//////////    return AuthorizationServerSettings.builder().issuer(issuer).build();
//////////  }
//////////
//////////  @Bean JWKSource<SecurityContext> jwkSource(@Value("${auth.jwks.dir:./data/jwks}") String dir) {
//////////    return new FileBackedJwks(dir);
//////////  }
//////////
//////////  @Bean RegisteredClientRepository registeredClientRepository(DataSource ds) {
//////////    return new JdbcRegisteredClientRepository(new JdbcTemplate(ds));
//////////  }
//////////
//////////  @Bean OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
//////////    return new JdbcOAuth2AuthorizationService(jdbc, repo);
//////////  }
//////////
//////////  @Bean OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
//////////    return new JdbcOAuth2AuthorizationConsentService(jdbc, repo);
//////////  }
//////////
//////////  @Bean
//////////  UserDetailsService users() {
//////////    return new InMemoryUserDetailsManager(
//////////            User.withUsername("user").password("{noop}password").roles("USER").build()
//////////    );
//////////  }
//////////}
//////////
////////
////////package com.example.authserver.config;
////////
////////import com.example.authserver.support.FileBackedJwks;
////////import com.nimbusds.jose.jwk.source.JWKSource;
////////import com.nimbusds.jose.proc.SecurityContext;
////////import org.springframework.beans.factory.annotation.Value;
////////import org.springframework.context.annotation.Bean;
////////import org.springframework.context.annotation.Configuration;
////////import org.springframework.core.Ordered;
////////import org.springframework.core.annotation.Order;
////////import org.springframework.jdbc.core.JdbcTemplate;
////////import org.springframework.security.config.Customizer;
////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////////import org.springframework.security.core.userdetails.User;
////////import org.springframework.security.core.userdetails.UserDetailsService;
////////import org.springframework.security.provisioning.InMemoryUserDetailsManager;
////////import org.springframework.security.web.SecurityFilterChain;
////////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
////////import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
////////import org.springframework.security.web.savedrequest.RequestCache;
////////import org.springframework.security.web.savedrequest.SavedRequest;
////////import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
////////import org.springframework.security.web.util.matcher.RequestMatcher;
////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
////////import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
////////import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
////////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
////////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
////////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
////////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
////////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
////////import org.springframework.web.cors.CorsConfiguration;
////////import org.springframework.web.cors.CorsConfigurationSource;
////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
////////
////////import javax.sql.DataSource;
////////import jakarta.servlet.http.HttpServletRequest;
////////import jakarta.servlet.http.HttpServletResponse;
////////import java.net.URI;
////////import java.util.List;
////////
////////@Configuration
////////@EnableWebSecurity
////////public class SecurityConfig {
////////
////////  /* ==================== RequestCache that ONLY saves /oauth2/authorize ==================== */
////////  @Bean
////////  RequestCache authorizeOnlyRequestCache() {
////////    return new HttpSessionRequestCache() {
////////      @Override
////////      public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
////////        // Save ONLY the original authorize request; ignore every other GET to prevent clobbering
////////        if ("GET".equalsIgnoreCase(request.getMethod())
////////                && "/oauth2/authorize".equals(request.getRequestURI())) {
////////          super.saveRequest(request, response);
////////        }
////////      }
////////    };
////////  }
////////
////////  /* ==================== Authorization Server chain ==================== */
////////  @Bean
////////  @Order(Ordered.HIGHEST_PRECEDENCE)
////////  SecurityFilterChain authorizationServerSecurityFilterChain(
////////          HttpSecurity http, RequestCache authorizeOnlyRequestCache) throws Exception {
////////
////////    var authz = new OAuth2AuthorizationServerConfigurer();
////////    authz.oidc(Customizer.withDefaults());
////////    RequestMatcher endpoints = authz.getEndpointsMatcher();
////////
////////    http.securityMatcher(endpoints)
////////            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
////////            .csrf(c -> c.ignoringRequestMatchers(endpoints))
////////            // Use our strict RequestCache so the SavedRequest is never replaced
////////            .requestCache(c -> c.requestCache(authorizeOnlyRequestCache))
////////            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
////////            .cors(Customizer.withDefaults())
////////            .apply(authz);
////////
////////    return http.build();
////////  }
////////
////////  /* ==================== Application chain (login UI, static, DCR) ==================== */
////////  @Bean
////////  SecurityFilterChain appSecurityFilterChain(
////////          HttpSecurity http, RequestCache authorizeOnlyRequestCache) throws Exception {
////////
////////    http
////////            .authorizeHttpRequests(auth -> auth
////////                    .requestMatchers(
////////                            new AntPathRequestMatcher("/connect/**"),
////////                            new AntPathRequestMatcher("/actuator/**"),
////////                            new AntPathRequestMatcher("/login"),
////////                            new AntPathRequestMatcher("/login/**"),
////////                            new AntPathRequestMatcher("/assets/**"),
////////                            new AntPathRequestMatcher("/csrf"),
////////                            new AntPathRequestMatcher("/"),
////////                            // 👇 allow noisy browser/extension hits so they don't trigger auth
////////                            new AntPathRequestMatcher("/favicon.ico"),
////////                            new AntPathRequestMatcher("/manifest*"),
////////                            new AntPathRequestMatcher("/robots.txt"),
////////                            new AntPathRequestMatcher("/.well-known/**")
////////                    ).permitAll()
////////                    .anyRequest().authenticated()
////////            )
////////            .formLogin(form -> form
////////                    .loginPage("/login")
////////                    .loginProcessingUrl("/login")
////////                    .successHandler((request, response, authentication) -> {
////////                      // 1) Prefer the SavedRequest (should be the original /oauth2/authorize?... URL)
////////                      SavedRequest saved = authorizeOnlyRequestCache.getRequest(request, response);
////////                      if (saved != null && saved.getRedirectUrl() != null) {
////////                        try {
////////                          URI u = URI.create(saved.getRedirectUrl());
////////                          if ("/oauth2/authorize".equals(u.getPath())) {
////////                            response.sendRedirect(saved.getRedirectUrl());
////////                            return;
////////                          }
////////                        } catch (Exception ignore) { /* fall through */ }
////////                      }
////////
////////                      // 2) Fallback to ?continue= posted by the login form (if present)
////////                      String cont = request.getParameter("continue");
////////                      if (cont != null && !cont.isBlank()) {
////////                        try {
////////                          URI u = URI.create(cont);
////////                          // same-origin guard
////////                          if (u.isAbsolute()) {
////////                            String host = request.getServerName();
////////                            int port = request.getServerPort();
////////                            if (!host.equalsIgnoreCase(u.getHost()) ||
////////                                    (u.getPort() != -1 && u.getPort() != port)) {
////////                              new SavedRequestAwareAuthenticationSuccessHandler()
////////                                      .onAuthenticationSuccess(request, response, authentication);
////////                              return;
////////                            }
////////                          }
////////                          response.sendRedirect(cont);
////////                          return;
////////                        } catch (Exception ignore) { /* fall through */ }
////////                      }
////////
////////                      // 3) Final fallback: default success ("/")
////////                      new SavedRequestAwareAuthenticationSuccessHandler()
////////                              .onAuthenticationSuccess(request, response, authentication);
////////                    })
////////                    .failureUrl("/login?error")
////////                    .permitAll()
////////            )
////////            // Use the same strict RequestCache here as well (defensive)
////////            .requestCache(c -> c.requestCache(authorizeOnlyRequestCache))
////////            .csrf(csrf -> csrf
////////                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////////                    .ignoringRequestMatchers(new AntPathRequestMatcher("/connect/**"))
////////            )
////////            .cors(Customizer.withDefaults());
////////
////////    return http.build();
////////  }
////////
////////  /* ==================== CORS & infrastructure beans ==================== */
////////  @Bean
////////  CorsConfigurationSource corsConfigurationSource() {
////////    CorsConfiguration cfg = new CorsConfiguration();
////////    cfg.setAllowedOrigins(List.of("http://localhost:5174", "http://localhost:5173"));
////////    cfg.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
////////    cfg.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With", "X-CSRF-TOKEN"));
////////    cfg.setAllowCredentials(true);
////////    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
////////    src.registerCorsConfiguration("/**", cfg);
////////    return src;
////////  }
////////
////////  @Bean
////////  AuthorizationServerSettings authorizationServerSettings(
////////          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer) {
////////    return AuthorizationServerSettings.builder().issuer(issuer).build();
////////  }
////////
////////  @Bean JWKSource<SecurityContext> jwkSource(@Value("${auth.jwks.dir:./data/jwks}") String dir) {
////////    return new FileBackedJwks(dir);
////////  }
////////
////////  @Bean RegisteredClientRepository registeredClientRepository(DataSource ds) {
////////    return new JdbcRegisteredClientRepository(new JdbcTemplate(ds));
////////  }
////////
////////  @Bean OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
////////    return new JdbcOAuth2AuthorizationService(jdbc, repo);
////////  }
////////
////////  @Bean OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
////////    return new JdbcOAuth2AuthorizationConsentService(jdbc, repo);
////////  }
////////
////////  @Bean
////////  UserDetailsService users() {
////////    return new InMemoryUserDetailsManager(
////////            User.withUsername("user").password("{noop}password").roles("USER").build()
////////    );
////////  }
////////}
//////
//////
//////package com.example.authserver.config;
//////
//////import com.example.authserver.support.FileBackedJwks;
//////import com.nimbusds.jose.jwk.source.JWKSource;
//////import com.nimbusds.jose.proc.SecurityContext;
//////import org.springframework.beans.factory.annotation.Value;
//////import org.springframework.context.annotation.Bean;
//////import org.springframework.context.annotation.Configuration;
//////import org.springframework.core.Ordered;
//////import org.springframework.core.annotation.Order;
//////import org.springframework.jdbc.core.JdbcTemplate;
//////import org.springframework.security.config.Customizer;
//////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//////import org.springframework.security.core.userdetails.User;
//////import org.springframework.security.core.userdetails.UserDetailsService;
//////import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//////import org.springframework.security.web.SecurityFilterChain;
//////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
//////import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//////import org.springframework.security.web.savedrequest.RequestCache;
//////import org.springframework.security.web.savedrequest.SavedRequest;
//////import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//////import org.springframework.security.web.util.matcher.RequestMatcher;
//////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//////import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
//////import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
//////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
//////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
//////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
//////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
//////import org.springframework.web.cors.CorsConfiguration;
//////import org.springframework.web.cors.CorsConfigurationSource;
//////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//////import javax.sql.DataSource;
//////import jakarta.servlet.http.HttpServletRequest;
//////import jakarta.servlet.http.HttpServletResponse;
//////import java.net.URI;
//////import java.util.List;
//////
//////@Configuration
//////@EnableWebSecurity
//////public class SecurityConfig {
//////
//////  /* ==================== RequestCache that ONLY saves /oauth2/authorize ==================== */
//////  @Bean
//////  RequestCache authorizeOnlyRequestCache() {
//////    return new HttpSessionRequestCache() {
//////      @Override
//////      public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
//////        if ("GET".equalsIgnoreCase(request.getMethod())
//////                && "/oauth2/authorize".equals(request.getRequestURI())) {
//////          super.saveRequest(request, response);
//////        }
//////      }
//////    };
//////  }
//////
//////  /* ==================== Authorization Server chain ==================== */
//////  @Bean
//////  @Order(Ordered.HIGHEST_PRECEDENCE)
//////  SecurityFilterChain authorizationServerSecurityFilterChain(
//////          HttpSecurity http, RequestCache authorizeOnlyRequestCache) throws Exception {
//////
//////    var authz = new OAuth2AuthorizationServerConfigurer();
//////    authz.oidc(Customizer.withDefaults());
//////    RequestMatcher endpoints = authz.getEndpointsMatcher();
//////
//////    http.securityMatcher(endpoints)
//////            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
//////            .csrf(c -> c.ignoringRequestMatchers(endpoints))
//////            .requestCache(c -> c.requestCache(authorizeOnlyRequestCache))
//////            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
//////            .cors(Customizer.withDefaults())
//////            .apply(authz);
//////
//////    return http.build();
//////  }
//////
//////  /* ==================== Application chain (login UI, static, DCR) ==================== */
//////  @Bean
//////  SecurityFilterChain appSecurityFilterChain(
//////          HttpSecurity http, RequestCache authorizeOnlyRequestCache) throws Exception {
//////
//////    http
//////            .authorizeHttpRequests(auth -> auth
//////                    .requestMatchers(
//////                            new AntPathRequestMatcher("/connect/**"),
//////                            new AntPathRequestMatcher("/actuator/**"),
//////                            new AntPathRequestMatcher("/login"),
//////                            new AntPathRequestMatcher("/login/**"),
//////                            new AntPathRequestMatcher("/assets/**"),
//////                            new AntPathRequestMatcher("/csrf"),
//////                            new AntPathRequestMatcher("/"),
//////                            new AntPathRequestMatcher("/favicon.ico"),
//////                            new AntPathRequestMatcher("/manifest*"),
//////                            new AntPathRequestMatcher("/robots.txt"),
//////                            new AntPathRequestMatcher("/.well-known/**")
//////                    ).permitAll()
//////                    .anyRequest().authenticated()
//////            )
//////            .formLogin(form -> form
//////                    .loginPage("/login")
//////                    .loginProcessingUrl("/login")
//////                    .successHandler((request, response, authentication) -> {
//////                      // 1) Resume original /oauth2/authorize request if present
//////                      SavedRequest saved = authorizeOnlyRequestCache.getRequest(request, response);
//////                      if (saved != null && saved.getRedirectUrl() != null) {
//////                        try {
//////                          URI u = URI.create(saved.getRedirectUrl());
//////                          if ("/oauth2/authorize".equals(u.getPath())) {
//////                            response.sendRedirect(saved.getRedirectUrl());
//////                            return;
//////                          }
//////                        } catch (Exception ignore) { }
//////                      }
//////
//////                      // 2) Use ?continue= if provided
//////                      String cont = request.getParameter("continue");
//////                      if (cont != null && !cont.isBlank()) {
//////                        try {
//////                          URI u = URI.create(cont);
//////                          if (u.isAbsolute()) {
//////                            String host = request.getServerName();
//////                            int port = request.getServerPort();
//////                            if (!host.equalsIgnoreCase(u.getHost()) ||
//////                                    (u.getPort() != -1 && u.getPort() != port)) {
//////                              new SavedRequestAwareAuthenticationSuccessHandler()
//////                                      .onAuthenticationSuccess(request, response, authentication);
//////                              return;
//////                            }
//////                          }
//////                          response.sendRedirect(cont);
//////                          return;
//////                        } catch (Exception ignore) { }
//////                      }
//////
//////                      // 3) Fallback: redirect to frontend (5174)
//////                      response.sendRedirect("http://localhost:5174/");
//////                    })
//////                    .failureUrl("/login?error")
//////                    .permitAll()
//////            )
//////            .requestCache(c -> c.requestCache(authorizeOnlyRequestCache))
//////            .csrf(csrf -> csrf
//////                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//////                    .ignoringRequestMatchers(new AntPathRequestMatcher("/connect/**"))
//////            )
//////            .cors(Customizer.withDefaults());
//////
//////    return http.build();
//////  }
//////
//////  /* ==================== CORS & infrastructure beans ==================== */
//////  @Bean
//////  CorsConfigurationSource corsConfigurationSource() {
//////    CorsConfiguration cfg = new CorsConfiguration();
//////    cfg.setAllowedOrigins(List.of("http://localhost:5174", "http://localhost:5173"));
//////    cfg.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
//////    cfg.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With", "X-CSRF-TOKEN"));
//////    cfg.setAllowCredentials(true);
//////    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
//////    src.registerCorsConfiguration("/**", cfg);
//////    return src;
//////  }
//////
//////  @Bean
//////  AuthorizationServerSettings authorizationServerSettings(
//////          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer) {
//////    return AuthorizationServerSettings.builder().issuer(issuer).build();
//////  }
//////
//////  @Bean JWKSource<SecurityContext> jwkSource(@Value("${auth.jwks.dir:./data/jwks}") String dir) {
//////    return new FileBackedJwks(dir);
//////  }
//////
//////  @Bean RegisteredClientRepository registeredClientRepository(DataSource ds) {
//////    return new JdbcRegisteredClientRepository(new JdbcTemplate(ds));
//////  }
//////
//////  @Bean OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
//////    return new JdbcOAuth2AuthorizationService(jdbc, repo);
//////  }
//////
//////  @Bean OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
//////    return new JdbcOAuth2AuthorizationConsentService(jdbc, repo);
//////  }
//////
//////  @Bean
//////  UserDetailsService users() {
//////    return new InMemoryUserDetailsManager(
//////            User.withUsername("user").password("{noop}password").roles("USER").build()
//////    );
//////  }
//////}
////
////
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
////import java.net.URLEncoder;
////import java.nio.charset.StandardCharsets;
////import java.util.Arrays;
////import java.util.List;
////
////import org.springframework.beans.factory.annotation.Value;
////import org.springframework.context.annotation.Bean;
////import org.springframework.context.annotation.Configuration;
////import org.springframework.core.Ordered;
////import org.springframework.core.annotation.Order;
////import org.springframework.jdbc.core.JdbcTemplate;
////import org.springframework.security.config.Customizer;
////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////import org.springframework.security.core.userdetails.User;
////import org.springframework.security.core.userdetails.UserDetailsService;
////import org.springframework.security.provisioning.InMemoryUserDetailsManager;
////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
////import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
////import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
////import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
////import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
////import org.springframework.security.web.SecurityFilterChain;
////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
////import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
////import org.springframework.security.web.savedrequest.RequestCache;
////import org.springframework.security.web.savedrequest.SavedRequest;
////import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
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
////    var authz = new OAuth2AuthorizationServerConfigurer();
////    authz.oidc(Customizer.withDefaults());
////    RequestMatcher endpoints = authz.getEndpointsMatcher();
////
////    http.securityMatcher(endpoints)
////            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
////            .csrf(c -> c.ignoringRequestMatchers(endpoints))
////            .requestCache(c -> c.requestCache(authorizeOnlyRequestCache))
////            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
////            .cors(Customizer.withDefaults())
////            .apply(authz);
////
////    // Entry point: preserve resume URL in THREE ways:
////    //   1) SavedRequest (via RequestCache above)
////    //   2) Short-lived HttpOnly cookie
////    //   3) Redirect to /login?continue=...
////    http.exceptionHandling(ex -> ex.authenticationEntryPoint((req, res, exn) -> {
////      String full = req.getRequestURL().toString();
////      String qs = req.getQueryString();
////      if (qs != null && !qs.isBlank()) full += "?" + qs;
////
////      Cookie c = new Cookie(CONT_COOKIE, URLEncoder.encode(full, StandardCharsets.UTF_8));
////      c.setHttpOnly(true);
////      c.setPath("/");
////      c.setMaxAge(120);
////      res.addCookie(c);
////
////      String loginWithContinue = "/login?continue=" + URLEncoder.encode(full, StandardCharsets.UTF_8);
////      res.setStatus(302);
////      res.setHeader("Location", loginWithContinue);
////    }));
////
////    return http.build();
////  }
////
////  /* ========= Application chain (login UI, static, DCR) ========= */
////  @Bean
////  SecurityFilterChain appSecurityFilterChain(
////          HttpSecurity http, RequestCache authorizeOnlyRequestCache) throws Exception {
////
////    // Capture Referer on GET /login as a last-chance resume source
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
////                        clearCookie(response, CONT_COOKIE);
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
////            .csrf(csrf -> csrf
////                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////                    .ignoringRequestMatchers(new AntPathRequestMatcher("/connect/**"))
////            )
////            .cors(Customizer.withDefaults());
////
////    return http.build();
////  }
////
////  /* ========= CORS (generic multi-client) ========= */
////  @Bean
////  CorsConfigurationSource corsConfigurationSource(
////          @Value("${CORS_ALLOWED_ORIGINS:}") String originsProperty) {
////
////    var cfg = new CorsConfiguration();
////    cfg.setAllowCredentials(true);
////
////    var configured = Arrays.stream(originsProperty.split(","))
////            .map(String::trim).filter(s -> !s.isEmpty()).toList();
////
////    if (configured.isEmpty()) {
////      cfg.setAllowedOriginPatterns(List.of(
////              "http://localhost:*",
////              "http://127.0.0.1:*",
////              "https://*.localtest.me"
////      ));
////    } else {
////      cfg.setAllowedOriginPatterns(configured);
////    }
////
////    cfg.setAllowedMethods(List.of("GET","POST","OPTIONS"));
////    cfg.setAllowedHeaders(List.of("Authorization","Content-Type","X-Requested-With","X-CSRF-TOKEN"));
////
////    var src = new UrlBasedCorsConfigurationSource();
////    src.registerCorsConfiguration("/**", cfg);
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
////  private static void clearCookie(HttpServletResponse res, String name) {
////    Cookie del = new Cookie(name, ""); del.setPath("/"); del.setMaxAge(0); res.addCookie(del);
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
//import java.util.Arrays;
//import java.util.List;
//
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.Ordered;
//import org.springframework.core.annotation.Order;
//import org.springframework.jdbc.core.JdbcTemplate;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
//import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
//import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
//import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
//import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
//import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//import org.springframework.security.web.savedrequest.RequestCache;
//import org.springframework.security.web.savedrequest.SavedRequest;
//import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//import org.springframework.security.web.util.matcher.RequestMatcher;
//import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
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
//  /** Save ONLY GET /oauth2/authorize so noise can’t overwrite it. */
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
//  /* ========= Authorization Server chain ========= */
//  @Bean
//  @Order(Ordered.HIGHEST_PRECEDENCE)
//  SecurityFilterChain authorizationServerSecurityFilterChain(
//          HttpSecurity http, RequestCache authorizeOnlyRequestCache) throws Exception {
//
//    var authz = new OAuth2AuthorizationServerConfigurer();
//    authz.oidc(Customizer.withDefaults());
//    RequestMatcher endpoints = authz.getEndpointsMatcher();
//
//    http.securityMatcher(endpoints)
//            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
//            .csrf(c -> c.ignoringRequestMatchers(endpoints))
//            .requestCache(c -> c.requestCache(authorizeOnlyRequestCache))
//            // Keep JWT resource server for endpoints like /userinfo,
//            // but make sure browsers get redirected to /login for /oauth2/authorize:
//            .exceptionHandling(ex -> ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
//            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
//            .cors(Customizer.withDefaults())
//            .apply(authz);
//
//    return http.build();
//  }
//
//  /* ========= Application chain (login UI, static, DCR) ========= */
//  @Bean
//  SecurityFilterChain appSecurityFilterChain(
//          HttpSecurity http, RequestCache authorizeOnlyRequestCache) throws Exception {
//
//    // Capture Referer on GET /login as a last-chance resume source
//    http.addFilterBefore(new LoginRefererCaptureFilter(CONT_COOKIE),
//            UsernamePasswordAuthenticationFilter.class);
//
//    // Prefer SavedRequest; fallback to cookie; lastly accept posted ?continue=
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
//                        Cookie del = new Cookie(CONT_COOKIE, ""); del.setPath("/"); del.setMaxAge(0); response.addCookie(del);
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
//            .csrf(csrf -> csrf
//                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                    .ignoringRequestMatchers(new AntPathRequestMatcher("/connect/**"))
//            )
//            .cors(Customizer.withDefaults());
//
//    return http.build();
//  }
//
//  /* ========= CORS (generic multi-client) ========= */
//  @Bean
//  CorsConfigurationSource corsConfigurationSource(
//          @Value("${CORS_ALLOWED_ORIGINS:}") String originsProperty) {
//
//    var cfg = new CorsConfiguration();
//    cfg.setAllowCredentials(true);
//
//    var configured = Arrays.stream(originsProperty.split(","))
//            .map(String::trim).filter(s -> !s.isEmpty()).toList();
//
//    if (configured.isEmpty()) {
//      cfg.setAllowedOriginPatterns(List.of(
//              "http://localhost:*",
//              "http://127.0.0.1:*",
//              "https://*.localtest.me"
//      ));
//    } else {
//      cfg.setAllowedOriginPatterns(configured);
//    }
//
//    cfg.setAllowedMethods(List.of("GET","POST","OPTIONS"));
//    cfg.setAllowedHeaders(List.of("Authorization","Content-Type","X-Requested-With","X-CSRF-TOKEN"));
//
//    var src = new UrlBasedCorsConfigurationSource();
//    src.registerCorsConfiguration("/**", cfg);
//    return src;
//  }
//
//  /* ========= Authorization Server infra ========= */
//  @Bean
//  AuthorizationServerSettings authorizationServerSettings(
//          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer) {
//    return AuthorizationServerSettings.builder().issuer(issuer).build();
//  }
//
//  @Bean JWKSource<SecurityContext> jwkSource(@Value("${auth.jwks.dir:./data/jwks}") String dir) {
//    return new FileBackedJwks(dir);
//  }
//
//  @Bean RegisteredClientRepository registeredClientRepository(DataSource ds) {
//    return new JdbcRegisteredClientRepository(new JdbcTemplate(ds));
//  }
//
//  @Bean OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
//    return new JdbcOAuth2AuthorizationService(jdbc, repo);
//  }
//
//  @Bean OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbc, RegisteredClientRepository repo) {
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
//  /* ===== helpers ===== */
//  private static boolean isAuthorizeUrl(String url) {
//    try { return "/oauth2/authorize".equals(URI.create(url).getPath()); }
//    catch (Exception e) { return false; }
//  }
//  private static String readCookie(HttpServletRequest req, String name) {
//    Cookie[] cs = req.getCookies(); if (cs == null) return null;
//    for (Cookie c : cs) if (name.equals(c.getName())) return c.getValue();
//    return null;
//  }
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
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  public static final String CONT_COOKIE = "CONTINUE";

  /** Save ONLY GET /oauth2/authorize so noise can’t overwrite it. */
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

  /* ========= Authorization Server chain ========= */
  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  SecurityFilterChain authorizationServerSecurityFilterChain(
          HttpSecurity http, RequestCache authorizeOnlyRequestCache) throws Exception {

    // Let SAS register all its endpoint filters (incl. /oauth2/token POST)
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    // Turn on OIDC (/.well-known/openid-configuration, /userinfo, etc.)
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());

    // Only HTML /oauth2/authorize requests should redirect to /login (browsers).
    // Token POST remains JSON (no redirect), which avoids 405.
    RequestMatcher htmlAny = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
    http
            .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"), htmlAny))
            .requestCache(c -> c.requestCache(authorizeOnlyRequestCache))
            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
            .cors(Customizer.withDefaults());

    return http.build();
  }

  /* ========= Application chain (login UI, static, DCR) ========= */
  @Bean
  SecurityFilterChain appSecurityFilterChain(
          HttpSecurity http, RequestCache authorizeOnlyRequestCache) throws Exception {

    // Capture Referer on GET /login as a last-chance resume source (sets CONTINUE cookie)
    http.addFilterBefore(new LoginRefererCaptureFilter(CONT_COOKIE),
            UsernamePasswordAuthenticationFilter.class);

    // Prefer SavedRequest; fallback to cookie; lastly accept posted ?continue=
    var savedHandler = new SavedRequestAwareAuthenticationSuccessHandler() {
      @Override
      protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        // 1) SavedRequest (/oauth2/authorize only)
        SavedRequest saved = authorizeOnlyRequestCache.getRequest(request, response);
        if (saved != null && isAuthorizeUrl(saved.getRedirectUrl())) {
          return saved.getRedirectUrl();
        }
        // 2) Cookie fallback
        String contCookie = readCookie(request, CONT_COOKIE);
        if (contCookie != null && !contCookie.isBlank()) {
          String cont = URLDecoder.decode(contCookie, StandardCharsets.UTF_8);
          if (sameOrigin(cont, request) && isAuthorizeUrl(cont)) return cont;
        }
        // 3) Posted hidden field from the login form
        String posted = request.getParameter("continue");
        if (posted != null && !posted.isBlank() && sameOrigin(posted, request) && isAuthorizeUrl(posted)) {
          return posted;
        }
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
                            new AntPathRequestMatcher("/.well-known/**")
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
                      response.getWriter().write(
                              "Login OK, but no original /oauth2/authorize request was found in session or cookie. " +
                                      "Please start from your application — it must call /oauth2/authorize with redirect_uri."
                      );
                    })
                    .failureUrl("/login?error")
                    .permitAll()
            )
            .requestCache(c -> c.requestCache(authorizeOnlyRequestCache))
            .csrf(csrf -> csrf
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                    .ignoringRequestMatchers(new AntPathRequestMatcher("/connect/**"))
            )
            .cors(Customizer.withDefaults());

    return http.build();
  }

  /* ========= CORS (generic multi-client) ========= */
//  @Bean
//  CorsConfigurationSource corsConfigurationSource(
//          @Value("${CORS_ALLOWED_ORIGINS:}") String originsProperty) {
//
//    var cfg = new CorsConfiguration();
//    cfg.setAllowCredentials(true);
//
//    var configured = Arrays.stream(originsProperty.split(","))
//            .map(String::trim).filter(s -> !s.isEmpty()).toList();
//
//    if (configured.isEmpty()) {
//      cfg.setAllowedOriginPatterns(List.of(
//              "http://localhost:*",
//              "http://127.0.0.1:*",
//              "https://*.localtest.me"
//      ));
//    } else {
//      cfg.setAllowedOriginPatterns(configured);
//    }
//
//    cfg.setAllowedMethods(List.of("GET","POST","OPTIONS"));
//    cfg.setAllowedHeaders(List.of("Authorization","Content-Type","X-Requested-With","X-CSRF-TOKEN"));
//
//    var src = new UrlBasedCorsConfigurationSource();
//    src.registerCorsConfiguration("/**", cfg);
//    return src;
//  }

  @Bean
  CorsConfigurationSource corsConfigurationSource(
          @Value("${CORS_ALLOWED_ORIGINS:}") String originsProperty) {

    CorsConfiguration cfg = new CorsConfiguration();
    cfg.setAllowCredentials(true);

    var configured = Arrays.stream(originsProperty.split(","))
            .map(String::trim).filter(s -> !s.isEmpty()).toList();

    if (configured.isEmpty()) {
      cfg.setAllowedOriginPatterns(List.of(
              "http://localhost:*",
              "http://127.0.0.1:*",
              "https://*.localtest.me"
      ));
    } else {
      cfg.setAllowedOriginPatterns(configured);
    }

    // 🔧 Be permissive to avoid odd 405/blocked preflights across endpoints
    cfg.addAllowedHeader("*");
    cfg.addAllowedMethod("*");   // GET, POST, OPTIONS, etc.

    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
    src.registerCorsConfiguration("/**", cfg);
    return src;
  }


  /* ========= Authorization Server infra ========= */
  @Bean
  AuthorizationServerSettings authorizationServerSettings(
          @Value("${AUTH_ISSUER_URI:http://localhost:8080}") String issuer) {
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

  @Bean
  UserDetailsService users() {
    return new InMemoryUserDetailsManager(
            User.withUsername("user").password("{noop}password").roles("USER").build()
    );
  }

  /* ===== helpers ===== */
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
