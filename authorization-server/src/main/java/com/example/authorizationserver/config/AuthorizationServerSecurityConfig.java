////////////////////////// authorization-server/src/main/java/com/example/authorizationserver/config/AuthorizationServerSecurityConfig.java
////////////////////////package com.example.authorizationserver.config;
////////////////////////
////////////////////////import org.springframework.context.annotation.Bean;
////////////////////////import org.springframework.context.annotation.Configuration;
////////////////////////import org.springframework.core.annotation.Order;
////////////////////////import org.springframework.http.HttpMethod;
////////////////////////import org.springframework.security.config.Customizer;
////////////////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////////////////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////////////////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
////////////////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
////////////////////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
////////////////////////import org.springframework.security.web.SecurityFilterChain;
////////////////////////
////////////////////////@Configuration
////////////////////////@EnableWebSecurity
////////////////////////public class AuthorizationServerSecurityConfig {
////////////////////////
////////////////////////    @Bean
////////////////////////    @Order(1)
////////////////////////    // authorization-server/.../AuthorizationServerSecurityConfig.java
////////////////////////    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
////////////////////////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
////////////////////////
////////////////////////        var as = http.getConfigurer(org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.class);
////////////////////////        var endpoints = as.getEndpointsMatcher();
////////////////////////        http.securityMatcher(endpoints);
////////////////////////
////////////////////////        // ⬇️ if not logged in, send to /login instead of whitelabel/500
////////////////////////        http.exceptionHandling(ex -> ex
////////////////////////                .authenticationEntryPoint(new org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint("/login"))
////////////////////////        );
////////////////////////
////////////////////////        as.oidc(Customizer.withDefaults());
////////////////////////        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
////////////////////////        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**","/.well-known/**"));
////////////////////////        return http.build();
////////////////////////    }
////////////////////////
//////////////////////////    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
//////////////////////////        // Register all OAuth2/OIDC endpoints and their security
//////////////////////////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//////////////////////////
//////////////////////////        // Keep OIDC enabled; do NOT enable SAS built-in DCR since you have your own controller
//////////////////////////        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//////////////////////////                .oidc(Customizer.withDefaults());
//////////////////////////
//////////////////////////        // Resource-server JWT for endpoints like revoke if needed
//////////////////////////        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
//////////////////////////
//////////////////////////        // CSRF: only ignore oauth2 endpoints here; /connect/register will be handled in @Order(2)
//////////////////////////        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**"));
//////////////////////////
//////////////////////////        return http.build();
//////////////////////////    }
////////////////////////
////////////////////////    @Bean
////////////////////////    @Order(2)
////////////////////////    SecurityFilterChain application(HttpSecurity http) throws Exception {
////////////////////////        http.authorizeHttpRequests(reg -> reg
////////////////////////                        // ✅ Permit your custom DCR endpoint here (not in @Order(1))
////////////////////////                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()
////////////////////////                        .requestMatchers("/login", "/error", "/actuator/**").permitAll()
////////////////////////                        .requestMatchers("/admin/clients").hasRole("ADMIN")
////////////////////////                        .anyRequest().authenticated()
////////////////////////                )
////////////////////////                .formLogin(Customizer.withDefaults())
////////////////////////                .httpBasic(Customizer.withDefaults())
////////////////////////                // ✅ Also ignore CSRF for your DCR endpoint here
////////////////////////                .csrf(csrf -> csrf.ignoringRequestMatchers("/connect/register", "/admin/clients"));
////////////////////////
////////////////////////        return http.build();
////////////////////////    }
////////////////////////
////////////////////////    @Bean
////////////////////////    AuthorizationServerSettings authorizationServerSettings() {
////////////////////////        return AuthorizationServerSettings.builder()
////////////////////////                .issuer("http://localhost:9000")
////////////////////////                .build();
////////////////////////    }
////////////////////////}
//////////////////////
//////////////////////
//////////////////////// authorization-server/src/main/java/com/example/authorizationserver/config/AuthorizationServerSecurityConfig.java
//////////////////////package com.example.authorizationserver.config;
//////////////////////
//////////////////////import org.springframework.context.annotation.Bean;
//////////////////////import org.springframework.context.annotation.Configuration;
//////////////////////import org.springframework.core.annotation.Order;
//////////////////////import org.springframework.http.HttpMethod;
//////////////////////import org.springframework.security.config.Customizer;
//////////////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//////////////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//////////////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//////////////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//////////////////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//////////////////////import org.springframework.security.web.SecurityFilterChain;
//////////////////////import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
//////////////////////
//////////////////////@Configuration
//////////////////////@EnableWebSecurity
//////////////////////public class AuthorizationServerSecurityConfig {
//////////////////////
//////////////////////    @Bean
//////////////////////    @Order(1)
//////////////////////    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
//////////////////////        // Register all OAuth2/OIDC endpoints and their default security (includes anyRequest().authenticated())
//////////////////////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//////////////////////
//////////////////////        // Scope this chain to the AS endpoints
//////////////////////        var as = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
//////////////////////        http.securityMatcher(as.getEndpointsMatcher());
//////////////////////
//////////////////////        // If not logged in, send to /login
//////////////////////        http.exceptionHandling(ex ->
//////////////////////                ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
//////////////////////        );
//////////////////////
//////////////////////        // Enable OIDC
//////////////////////        as.oidc(Customizer.withDefaults());
//////////////////////
//////////////////////        // Resource server (JWT) for endpoints like revoke/introspect if needed
//////////////////////        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
//////////////////////
//////////////////////        // Enable CORS processing on this chain (actual policy provided by CorsConfigurationSource bean)
//////////////////////        http.cors(Customizer.withDefaults());
//////////////////////
//////////////////////        // Ignore CSRF for core OAuth2/OIDC endpoints
//////////////////////        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**"));
//////////////////////
//////////////////////        return http.build();
//////////////////////    }
//////////////////////
//////////////////////    @Bean
//////////////////////    @Order(2)
//////////////////////    SecurityFilterChain application(HttpSecurity http) throws Exception {
//////////////////////        http
//////////////////////                .authorizeHttpRequests(reg -> reg
//////////////////////                        // Allow CORS preflight for app endpoints
//////////////////////                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
//////////////////////
//////////////////////                        // Your custom DCR endpoint is open (controller validates initial token)
//////////////////////                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()
//////////////////////
//////////////////////                        // Public pages
//////////////////////                        .requestMatchers("/login", "/error", "/actuator/**").permitAll()
//////////////////////
//////////////////////                        // Admin API
//////////////////////                        .requestMatchers("/admin/clients").hasRole("ADMIN")
//////////////////////
//////////////////////                        // Everything else requires auth
//////////////////////                        .anyRequest().authenticated()
//////////////////////                )
//////////////////////                .formLogin(Customizer.withDefaults())
//////////////////////                .httpBasic(Customizer.withDefaults())
//////////////////////
//////////////////////                // Enable CORS on this chain
//////////////////////                .cors(Customizer.withDefaults())
//////////////////////
//////////////////////                // Ignore CSRF for JSON endpoints you call from the React app
//////////////////////                .csrf(csrf -> csrf.ignoringRequestMatchers("/connect/register", "/admin/clients"));
//////////////////////
//////////////////////        return http.build();
//////////////////////    }
//////////////////////
//////////////////////    @Bean
//////////////////////    AuthorizationServerSettings authorizationServerSettings() {
//////////////////////        return AuthorizationServerSettings.builder()
//////////////////////                .issuer("http://localhost:9000")
//////////////////////                .build();
//////////////////////    }
//////////////////////}
////////////////////
////////////////////
////////////////////// authorization-server/src/main/java/com/example/authorizationserver/config/AuthorizationServerSecurityConfig.java
////////////////////package com.example.authorizationserver.config;
////////////////////
////////////////////import org.springframework.context.annotation.Bean;
////////////////////import org.springframework.context.annotation.Configuration;
////////////////////import org.springframework.core.annotation.Order;
////////////////////import org.springframework.http.HttpMethod;
////////////////////import org.springframework.security.config.Customizer;
////////////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////////////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////////////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
////////////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
////////////////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
////////////////////import org.springframework.security.web.SecurityFilterChain;
////////////////////import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
////////////////////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
////////////////////
////////////////////@Configuration
////////////////////@EnableWebSecurity
////////////////////public class AuthorizationServerSecurityConfig {
////////////////////
////////////////////    /**
////////////////////     * Chain for the OAuth2 / OIDC endpoints exposed by Spring Authorization Server.
////////////////////     * Do NOT add extra matchers here; SAS registers authorizeHttpRequests with anyRequest().authenticated().
////////////////////     */
////////////////////    @Bean
////////////////////    @Order(1)
////////////////////    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
////////////////////        // 1) Register SAS defaults (issuer endpoints, filters, etc.)
////////////////////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
////////////////////
////////////////////        // 2) Scope this chain strictly to SAS endpoints
////////////////////        OAuth2AuthorizationServerConfigurer as = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
////////////////////        http.securityMatcher(as.getEndpointsMatcher());
////////////////////
////////////////////        // 3) If not authenticated, go to our custom login page
////////////////////        http.exceptionHandling(ex -> ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login")));
////////////////////
////////////////////        // 4) Enable OIDC on SAS
////////////////////        as.oidc(Customizer.withDefaults());
////////////////////
////////////////////        // 5) Enable resource server JWT for revoke/introspect flows if needed
////////////////////        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
////////////////////
////////////////////        // 6) Enable CORS (policy provided via a CorsConfigurationSource bean)
////////////////////        http.cors(Customizer.withDefaults());
////////////////////
////////////////////        // 7) CSRF is not needed for machine-to-machine OAuth endpoints
////////////////////        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**"));
////////////////////
////////////////////        return http.build();
////////////////////    }
////////////////////
////////////////////    /**
////////////////////     * Chain for your application endpoints (login page, admin API, DCR, etc.).
////////////////////     */
////////////////////    @Bean
////////////////////    @Order(2)
////////////////////    SecurityFilterChain application(HttpSecurity http) throws Exception {
////////////////////        http
////////////////////                .authorizeHttpRequests(reg -> reg
////////////////////                        // Allow CORS preflight
////////////////////                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
////////////////////
////////////////////                        // Public assets for your React login page
////////////////////                        .requestMatchers("/auth/login", "/auth/login/**", "/login", "/error", "/actuator/**").permitAll()
////////////////////
////////////////////                        // Dynamic Client Registration: controller validates initial token header; allow unauthenticated POST
////////////////////                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()
////////////////////
////////////////////                        // Admin API requires ADMIN role
////////////////////                        .requestMatchers("/admin/clients").hasRole("ADMIN")
////////////////////
////////////////////                        // Everything else requires auth
////////////////////                        .anyRequest().authenticated()
////////////////////                )
////////////////////
////////////////////                // Use your custom React login page for GET, Spring handles POST /login
////////////////////                .formLogin(form -> form
////////////////////                        .loginPage("/auth/login")
////////////////////                        .loginProcessingUrl("/login")
////////////////////                        // .defaultSuccessUrl("/", true) // uncomment if you want a fixed post-login redirect
////////////////////                        .permitAll()
////////////////////                )
////////////////////
////////////////////                // Basic auth (for admin API via curl / programmatic calls)
////////////////////                .httpBasic(Customizer.withDefaults())
////////////////////
////////////////////                // CORS for browser apps (policy from CorsConfigurationSource)
////////////////////                .cors(Customizer.withDefaults())
////////////////////
////////////////////                // CSRF:
////////////////////                //  - Use cookie-based token so your React page can read XSRF-TOKEN and send it back as _csrf
////////////////////                //  - Ignore CSRF for JSON endpoints you call via fetch (admin & DCR)
////////////////////                .csrf(csrf -> csrf
////////////////////                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////////////////////                        .ignoringRequestMatchers("/connect/register", "/admin/clients")
////////////////////                );
////////////////////
////////////////////        return http.build();
////////////////////    }
////////////////////
////////////////////    /**
////////////////////     * Authorization Server settings: set the issuer URL explicitly.
////////////////////     */
////////////////////    @Bean
////////////////////    AuthorizationServerSettings authorizationServerSettings() {
////////////////////        return AuthorizationServerSettings.builder()
////////////////////                .issuer("http://localhost:9000")
////////////////////                .build();
////////////////////    }
////////////////////}
//////////////////
//////////////////
//////////////////
//////////////////// authorization-server/src/main/java/com/example/authorizationserver/config/AuthorizationServerSecurityConfig.java
//////////////////package com.example.authorizationserver.config;
//////////////////
//////////////////import org.springframework.context.annotation.Bean;
//////////////////import org.springframework.context.annotation.Configuration;
//////////////////import org.springframework.core.annotation.Order;
//////////////////import org.springframework.http.HttpMethod;
//////////////////import org.springframework.security.config.Customizer;
//////////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//////////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//////////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//////////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//////////////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//////////////////import org.springframework.security.web.SecurityFilterChain;
//////////////////import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
//////////////////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
//////////////////
//////////////////@Configuration
//////////////////@EnableWebSecurity
//////////////////public class AuthorizationServerSecurityConfig {
//////////////////
//////////////////    /**
//////////////////     * Security chain for Spring Authorization Server (SAS) endpoints:
//////////////////     * /oauth2/**, /.well-known/**, /connect/** (OIDC), etc.
//////////////////     */
//////////////////    @Bean
//////////////////    @Order(1)
//////////////////    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
//////////////////        // Register SAS defaults (adds its own authorize rules)
//////////////////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//////////////////
//////////////////        // Scope this chain strictly to SAS endpoints
//////////////////        OAuth2AuthorizationServerConfigurer as = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
//////////////////        http.securityMatcher(as.getEndpointsMatcher());
//////////////////
//////////////////        // Unauthenticated → send to our custom login page (served by the app chain)
//////////////////        http.exceptionHandling(ex ->
//////////////////                ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login"))
//////////////////        );
//////////////////
//////////////////        // Enable OIDC on SAS
//////////////////        as.oidc(Customizer.withDefaults());
//////////////////
//////////////////        // Resource-server JWT for endpoints like revoke/introspect if needed
//////////////////        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
//////////////////
//////////////////        // CORS processing (policy provided by a CorsConfigurationSource bean)
//////////////////        http.cors(Customizer.withDefaults());
//////////////////
//////////////////        // CSRF is not needed for machine-to-machine OAuth2/OIDC endpoints
//////////////////        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**"));
//////////////////
//////////////////        return http.build();
//////////////////    }
//////////////////
//////////////////    /**
//////////////////     * Security chain for your application endpoints:
//////////////////     * custom React login page (/auth/login), admin API, DCR, static assets, etc.
//////////////////     */
//////////////////    @Bean
//////////////////    @Order(2)
//////////////////    SecurityFilterChain application(HttpSecurity http) throws Exception {
//////////////////        http
//////////////////                .authorizeHttpRequests(reg -> reg
//////////////////                        // Allow preflight for CORS
//////////////////                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
//////////////////
//////////////////                        // Public routes & static assets needed by your React login page
//////////////////                        .requestMatchers(
//////////////////                                "/auth/login", "/auth/login/**",
//////////////////                                "/login",              // GET fallback & POST processing URL
//////////////////                                "/admin/clients", "/admin/clients/**",   // serve SPA
//////////////////                                "/css/**", "/js/**", "/assets/**", "/images/**",
//////////////////                                "/favicon.ico", "/error", "/actuator/**"
//////////////////                        ).permitAll()
//////////////////
//////////////////                        // Dynamic Client Registration (controller validates initial token)
//////////////////                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()
//////////////////
//////////////////                        .requestMatchers(org.springframework.http.HttpMethod.GET, "/admin/clients")
//////////////////                        .permitAll() // HTML page (the SPA)
//////////////////                        .requestMatchers(org.springframework.http.HttpMethod.GET, "/admin/clients")
//////////////////                        .permitAll()
//////////////////
//////////////////                        // Admin API requires ADMIN role
//////////////////                        .requestMatchers("/admin/clients").hasRole("ADMIN")
//////////////////
//////////////////                        // Everything else requires authentication
//////////////////                        .anyRequest().authenticated()
//////////////////                )
//////////////////
//////////////////                // >>> Your custom React login page (GET /auth/login), POST still goes to /login
//////////////////                .formLogin(form -> form
//////////////////                        .loginPage("/auth/login")      // serve your React page here
//////////////////                        .loginProcessingUrl("/login")   // Spring Security processes form POST here
//////////////////                         .defaultSuccessUrl("/", true) // optional: force a fixed success URL
////////////////////                        .defaultSuccessUrl("/admin/clients", true) // always go here
//////////////////
//////////////////                        .permitAll()
//////////////////                )
//////////////////
//////////////////                // Basic auth for curl / programmatic calls (e.g., admin endpoints)
//////////////////                .httpBasic(Customizer.withDefaults())
//////////////////
//////////////////                // Enable CORS for browser apps (policy from CorsConfigurationSource bean)
//////////////////                .cors(Customizer.withDefaults())
//////////////////
//////////////////                // CSRF:
//////////////////                // - Use cookie-based token so your React page (served under /auth/login) can read XSRF-TOKEN
//////////////////                // - DO NOT ignore /login (so CSRF protects the login POST)
//////////////////                // - Keep ignores for JSON endpoints you call via fetch (admin & DCR)
//////////////////                .csrf(csrf -> csrf
//////////////////                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//////////////////                        .ignoringRequestMatchers("/connect/register", "/admin/clients")
//////////////////                );
//////////////////
//////////////////        return http.build();
//////////////////    }
//////////////////
//////////////////    /**
//////////////////     * Authorization Server settings (issuer, etc.).
//////////////////     */
//////////////////    @Bean
//////////////////    AuthorizationServerSettings authorizationServerSettings() {
//////////////////        return AuthorizationServerSettings.builder()
//////////////////                .issuer("http://localhost:9000")
//////////////////                .build();
//////////////////    }
//////////////////}
////////////////
////////////////
////////////////// authorization-server/src/main/java/com/example/authorizationserver/config/AuthorizationServerSecurityConfig.java
////////////////package com.example.authorizationserver.config;
////////////////
////////////////import org.springframework.context.annotation.Bean;
////////////////import org.springframework.context.annotation.Configuration;
////////////////import org.springframework.core.annotation.Order;
////////////////import org.springframework.http.HttpMethod;
////////////////import org.springframework.security.config.Customizer;
////////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
////////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
////////////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
////////////////import org.springframework.security.web.DefaultRedirectStrategy;
////////////////import org.springframework.security.web.SecurityFilterChain;
////////////////import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
////////////////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
////////////////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
////////////////import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
////////////////import org.springframework.security.web.savedrequest.SavedRequest;
////////////////import org.springframework.security.core.Authentication;
////////////////import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
////////////////
////////////////import jakarta.servlet.http.HttpServletRequest;
////////////////import jakarta.servlet.http.HttpServletResponse;
////////////////
////////////////@Configuration
////////////////@EnableWebSecurity
////////////////public class AuthorizationServerSecurityConfig {
////////////////
////////////////    @Bean
////////////////    @Order(1)
////////////////    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
////////////////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
////////////////
////////////////        OAuth2AuthorizationServerConfigurer as = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
////////////////        http.securityMatcher(as.getEndpointsMatcher());
////////////////
////////////////        http.exceptionHandling(ex ->
////////////////                ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login"))
////////////////        );
////////////////
////////////////        as.oidc(Customizer.withDefaults());
////////////////        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
////////////////        http.cors(Customizer.withDefaults());
////////////////        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**","/.well-known/**"));
////////////////        return http.build();
////////////////    }
////////////////
////////////////    @Bean
////////////////    @Order(2)
////////////////    SecurityFilterChain application(HttpSecurity http) throws Exception {
////////////////        // Smart success handler:
////////////////        var savedHandler = new SavedRequestAwareAuthenticationSuccessHandler();
////////////////        savedHandler.setDefaultTargetUrl("http://localhost:5173/");
////////////////        savedHandler.setAlwaysUseDefaultTargetUrl(false);
////////////////
////////////////        var requestCache = new HttpSessionRequestCache();
////////////////        var redirect = new DefaultRedirectStrategy();
////////////////
//////////////////        var successHandler = (org.springframework.security.web.authentication.AuthenticationSuccessHandler)
//////////////////                (HttpServletRequest req, HttpServletResponse res, var auth) -> {
////////////////
////////////////        AuthenticationSuccessHandler successHandler = (HttpServletRequest req,
////////////////                                                       HttpServletResponse res,
////////////////                                                       Authentication auth) -> {
////////////////                    SavedRequest saved = requestCache.getRequest(req, res);
////////////////
////////////////
////////////////                    if (saved != null) {
////////////////                        String url = saved.getRedirectUrl();
////////////////                        // If the saved URL is our CSRF helper or a stray login alias, skip it.
////////////////                        if (url.contains("/auth/csrf") || url.contains("/oauth/login")) {
////////////////                            redirect.sendRedirect(req, res, "http://localhost:5173/");
////////////////                            return;
////////////////                        }
////////////////                    }
////////////////                    savedHandler.onAuthenticationSuccess(req, res, auth);
////////////////                };
////////////////
////////////////        http
////////////////                .authorizeHttpRequests(reg -> reg
////////////////                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
////////////////                        .requestMatchers(
////////////////                                "/auth/login","/auth/login/**",
////////////////                                "/login",
////////////////                                "/oauth/login",        // permit stray path
////////////////                                "/auth/csrf",          // CSRF JSON helper
////////////////                                "/assets/**","/css/**","/js/**","/images/**",
////////////////                                "/favicon.ico","/error","/actuator/**"
////////////////                        ).permitAll()
////////////////                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()
////////////////                        .requestMatchers("/admin/clients").hasRole("ADMIN")
////////////////                        .anyRequest().authenticated()
////////////////                )
////////////////                .formLogin(form -> form
////////////////                        .loginPage("/auth/login")
////////////////                        .loginProcessingUrl("/login")
////////////////                        .successHandler(successHandler)   // <— use the smart handler
////////////////                        .permitAll()
////////////////                )
////////////////                .httpBasic(Customizer.withDefaults())
////////////////                .cors(Customizer.withDefaults())
////////////////                .csrf(csrf -> csrf
////////////////                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////////////////                        .ignoringRequestMatchers("/connect/register")  // add more JSON POSTs if needed
////////////////                );
////////////////
////////////////        // ensure Spring uses the same cache we read above
////////////////        http.requestCache(rc -> rc.requestCache(requestCache));
////////////////
////////////////        return http.build();
////////////////    }
////////////////
////////////////    @Bean
////////////////    AuthorizationServerSettings authorizationServerSettings() {
////////////////        return AuthorizationServerSettings.builder()
////////////////                .issuer("http://localhost:9000")
////////////////                .build();
////////////////    }
////////////////}
//////////////
//////////////// authorization-server/src/main/java/com/example/authorizationserver/config/AuthorizationServerSecurityConfig.java
//////////////package com.example.authorizationserver.config;
//////////////
//////////////import com.example.authorizationserver.web.AlreadyAuthenticatedLoginBypassFilter;
//////////////import jakarta.servlet.http.HttpServletRequest;
//////////////import jakarta.servlet.http.HttpServletResponse;
//////////////import org.springframework.context.annotation.Bean;
//////////////import org.springframework.context.annotation.Configuration;
//////////////import org.springframework.core.annotation.Order;
//////////////import org.springframework.http.HttpMethod;
//////////////import org.springframework.security.config.Customizer;
//////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//////////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//////////////import org.springframework.security.web.DefaultRedirectStrategy;
//////////////import org.springframework.security.web.SecurityFilterChain;
//////////////import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//////////////import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
//////////////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
//////////////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//////////////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
//////////////import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//////////////import org.springframework.security.web.savedrequest.SavedRequest;
//////////////
//////////////@Configuration
//////////////@EnableWebSecurity
//////////////public class AuthorizationServerSecurityConfig {
//////////////
//////////////    private final AuthUiProperties uiProps;
//////////////
//////////////    public AuthorizationServerSecurityConfig(AuthUiProperties uiProps) {
//////////////        this.uiProps = uiProps;
//////////////    }
//////////////
//////////////    @Bean
//////////////    @Order(1)
//////////////    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
//////////////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//////////////        OAuth2AuthorizationServerConfigurer as = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
//////////////        http.securityMatcher(as.getEndpointsMatcher());
//////////////
//////////////        http.exceptionHandling(ex ->
//////////////                ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login"))
//////////////        );
//////////////
//////////////        as.oidc(Customizer.withDefaults());
//////////////        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
//////////////        http.cors(Customizer.withDefaults());
//////////////        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**","/.well-known/**"));
//////////////
//////////////        return http.build();
//////////////    }
//////////////
//////////////    @Bean
//////////////    @Order(2)
//////////////    SecurityFilterChain application(HttpSecurity http) throws Exception {
//////////////        // Saved-request aware handler with generic fallback
//////////////        var savedHandler = new SavedRequestAwareAuthenticationSuccessHandler();
//////////////        savedHandler.setDefaultTargetUrl(uiProps.getDefaultSuccessUrl());
//////////////        savedHandler.setAlwaysUseDefaultTargetUrl(false);
//////////////
//////////////        var requestCache = new HttpSessionRequestCache();
//////////////        var redirect = new DefaultRedirectStrategy();
//////////////
//////////////        AuthenticationSuccessHandler successHandler = (HttpServletRequest req,
//////////////                                                       HttpServletResponse res,
//////////////                                                       org.springframework.security.core.Authentication auth) -> {
//////////////            SavedRequest saved = requestCache.getRequest(req, res);
//////////////            if (saved != null) {
//////////////                String url = saved.getRedirectUrl();
//////////////                // If the saved URL is an internal helper (like /auth/csrf), ignore it
//////////////                for (String bad : uiProps.getIgnoreSavedRequestContains()) {
//////////////                    if (url.contains(bad)) {
//////////////                        redirect.sendRedirect(req, res, req.getContextPath() + uiProps.getDefaultSuccessUrl());
//////////////                        return;
//////////////                    }
//////////////                }
//////////////            }
//////////////            savedHandler.onAuthenticationSuccess(req, res, auth);
//////////////        };
//////////////
//////////////        http
//////////////                .authorizeHttpRequests(reg -> reg
//////////////                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
//////////////                        .requestMatchers(
//////////////                                "/auth/login","/auth/login/**",
//////////////                                "/login", "/oauth/login",    // GET /login forward; POST /login processing
//////////////                                "/auth/csrf",                // CSRF helper (permit to avoid being saved)
//////////////                                "/assets/**","/css/**","/js/**","/images/**",
//////////////                                "/favicon.ico","/error","/actuator/**"
//////////////                        ).permitAll()
//////////////                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()
//////////////                        .requestMatchers("/admin/clients").hasRole("ADMIN")
//////////////                        .anyRequest().authenticated()
//////////////                )
//////////////                .formLogin(form -> form
//////////////                        .loginPage("/auth/login")
//////////////                        .loginProcessingUrl("/login")
//////////////                        .successHandler(successHandler)
//////////////                        .permitAll()
//////////////                )
//////////////                .httpBasic(Customizer.withDefaults())
//////////////                .cors(Customizer.withDefaults())
//////////////                .csrf(csrf -> csrf
//////////////                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//////////////                        .ignoringRequestMatchers("/connect/register")
//////////////                );
//////////////
//////////////        // Bypass “second POST /login” without hardcoded host
//////////////        http.addFilterBefore(
//////////////                new AlreadyAuthenticatedLoginBypassFilter(uiProps.getDefaultSuccessUrl()),
//////////////                UsernamePasswordAuthenticationFilter.class
//////////////        );
//////////////
//////////////        http.requestCache(rc -> rc.requestCache(requestCache));
//////////////        return http.build();
//////////////    }
//////////////
//////////////    @Bean
//////////////    AuthorizationServerSettings authorizationServerSettings() {
//////////////        return AuthorizationServerSettings.builder()
//////////////                .issuer("http://localhost:9000")
//////////////                .build();
//////////////    }
//////////////}
////////////
////////////// authorization-server/src/main/java/com/example/authorizationserver/config/AuthorizationServerSecurityConfig.java
////////////package com.example.authorizationserver.config;
////////////
////////////import org.springframework.context.annotation.Bean;
////////////import org.springframework.context.annotation.Configuration;
////////////import org.springframework.core.annotation.Order;
////////////import org.springframework.http.HttpMethod;
////////////import org.springframework.security.config.Customizer;
////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
////////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
////////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
////////////import org.springframework.security.web.SecurityFilterChain;
////////////import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
////////////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
////////////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
////////////
////////////@Configuration
////////////@EnableWebSecurity
////////////public class AuthorizationServerSecurityConfig {
////////////
////////////    /**
////////////     * Chain for SAS endpoints (/oauth2/**, /.well-known/**, /connect/**).
////////////     * Unauthenticated access to these should go to our custom login page.
////////////     */
////////////    @Bean
////////////    @Order(1)
////////////    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
////////////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
////////////
////////////        OAuth2AuthorizationServerConfigurer as = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
////////////        http.securityMatcher(as.getEndpointsMatcher());
////////////
////////////        http.exceptionHandling(ex ->
////////////                ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login"))
////////////        );
////////////
////////////        as.oidc(Customizer.withDefaults());
////////////        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
////////////        http.cors(Customizer.withDefaults());
////////////        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**"));
////////////
////////////        return http.build();
////////////    }
////////////
////////////    /**
////////////     * Chain for app routes (custom login UI, static assets, admin JSON, etc).
////////////     * Important: we use Spring’s SavedRequestAwareAuthenticationSuccessHandler
////////////     * so that after login we return to the original saved request
////////////     * (e.g., /oauth2/authorize?...), which then redirects to the client’s redirect_uri.
////////////     */
////////////    @Bean
////////////    @Order(2)
////////////    SecurityFilterChain application(HttpSecurity http) throws Exception {
////////////        var savedHandler = new SavedRequestAwareAuthenticationSuccessHandler();
////////////        // NOTE: we do NOT set a default success URL here — let the saved request drive it.
////////////
////////////        http
////////////                .authorizeHttpRequests(reg -> reg
////////////                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
////////////
////////////                        // Public pages & static assets for your React login
////////////                        .requestMatchers(
////////////                                "/auth/login", "/auth/login/**",
////////////                                "/login",              // GET redirect; POST is processing
////////////                                "/oauth/login",        // convenience alias → /auth/login
////////////                                "/auth/csrf",          // CSRF helper JSON
////////////                                "/landing",            // neutral landing page
////////////                                "/assets/**", "/css/**", "/js/**", "/images/**",
////////////                                "/favicon.ico", "/error", "/actuator/**"
////////////                        ).permitAll()
////////////
////////////                        // DCR endpoint (your code will validate its initial token)
////////////                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()
////////////
////////////                        // Admin API protected by role
////////////                        .requestMatchers("/admin/clients").hasRole("ADMIN")
////////////
////////////                        .anyRequest().authenticated()
////////////                )
////////////                .formLogin(form -> form
////////////                        .loginPage("/auth/login")
////////////                        .loginProcessingUrl("/login")
////////////                        .successHandler(savedHandler) // <— key: resume saved request (oauth2/authorize)
////////////                        .permitAll()
////////////                )
////////////                .httpBasic(Customizer.withDefaults())
////////////                .cors(Customizer.withDefaults())
////////////                .csrf(csrf -> csrf
////////////                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////////////                        // ignore JSON posts you don’t want CSRF on:
////////////                        .ignoringRequestMatchers("/connect/register")
////////////                );
////////////
////////////        // No default target, no hard-coded client URL; saved request will handle redirects.
////////////        return http.build();
////////////    }
////////////
////////////    @Bean
////////////    AuthorizationServerSettings authorizationServerSettings() {
////////////        return AuthorizationServerSettings.builder()
////////////                .issuer("http://localhost:9000")
////////////                .build();
////////////    }
////////////}
//////////
//////////package com.example.authorizationserver.config;
//////////
//////////import org.springframework.context.annotation.Bean;
//////////import org.springframework.context.annotation.Configuration;
//////////import org.springframework.core.annotation.Order;
//////////import org.springframework.http.HttpMethod;
//////////import org.springframework.security.config.Customizer;
//////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//////////import org.springframework.security.web.SecurityFilterChain;
//////////import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
//////////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
//////////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
//////////
//////////@Configuration
//////////@EnableWebSecurity
//////////public class AuthorizationServerSecurityConfig {
//////////
//////////    /**
//////////     * Chain for SAS endpoints (/oauth2/**, /.well-known/**, /connect/**).
//////////     * If unauthenticated, send to our React login page (/auth/login).
//////////     */
//////////    @Bean
//////////    @Order(1)
//////////    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
//////////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//////////
//////////        OAuth2AuthorizationServerConfigurer as = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
//////////        http.securityMatcher(as.getEndpointsMatcher());
//////////
//////////        http.exceptionHandling(ex ->
//////////                ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login"))
//////////        );
//////////
//////////        as.oidc(Customizer.withDefaults());
//////////        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
//////////        http.cors(Customizer.withDefaults());
//////////        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**"));
//////////
//////////        return http.build();
//////////    }
//////////
//////////    /**
//////////     * Chain for app routes (custom login UI, static assets, admin JSON, etc).
//////////     * IMPORTANT: Use SavedRequestAwareAuthenticationSuccessHandler so that after login
//////////     * Spring resumes the original /oauth2/authorize request (which then redirects to the client's redirect_uri).
//////////     */
//////////    @Bean
//////////    @Order(2)
//////////    SecurityFilterChain application(HttpSecurity http) throws Exception {
//////////        var savedHandler = new SavedRequestAwareAuthenticationSuccessHandler();
//////////        // Do NOT set a default success URL — let the saved request (authorize URL) drive the redirect.
//////////
//////////        http
//////////                .authorizeHttpRequests(reg -> reg
//////////                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
//////////
//////////                        // Public routes & static assets for your React login and landing page
//////////                        .requestMatchers(
//////////                                "/auth/login", "/auth/login/**",
//////////                                "/login",              // GET redirect → /auth/login ; POST is the processing URL
//////////                                "/oauth/login",        // alias → /auth/login
//////////                                "/auth/csrf",          // CSRF helper JSON (if you expose it)
//////////                                "/landing",            // neutral internal landing page
//////////                                "/assets/**", "/css/**", "/js/**", "/images/**",
//////////                                "/favicon.ico", "/error", "/actuator/**"
//////////                        ).permitAll()
//////////
//////////                        // Dynamic Client Registration endpoint — your controller will validate any initial token
//////////                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()
//////////
//////////                        // Admin JSON API — protect by role (and optionally @PreAuthorize on controller)
//////////                        .requestMatchers("/admin/clients").hasRole("ADMIN")
//////////
//////////                        .anyRequest().authenticated()
//////////                )
//////////                .formLogin(form -> form
//////////                        .loginPage("/auth/login")       // served by our controller below
//////////                        .loginProcessingUrl("/login")    // POST endpoint Spring Security consumes
//////////                        .successHandler(savedHandler)    // <-- resume saved request (e.g., /oauth2/authorize)
//////////                        .permitAll()
//////////                )
//////////                .httpBasic(Customizer.withDefaults())
//////////                .cors(Customizer.withDefaults())
//////////                .csrf(csrf -> csrf
//////////                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//////////                        // ignore CSRF on machine-to-machine JSON POSTs you explicitly want open:
//////////                        .ignoringRequestMatchers("/connect/register")
//////////                );
//////////
//////////        return http.build();
//////////    }
//////////
//////////    @Bean
//////////    AuthorizationServerSettings authorizationServerSettings() {
//////////        return AuthorizationServerSettings.builder()
//////////                .issuer("http://localhost:9000")
//////////                .build();
//////////    }
//////////}
////////
////////
////////package com.example.authorizationserver.config;
////////
////////import org.springframework.context.annotation.Bean;
////////import org.springframework.context.annotation.Configuration;
////////import org.springframework.core.annotation.Order;
////////import org.springframework.http.HttpMethod;
////////import org.springframework.security.config.Customizer;
////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
////////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
////////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
////////import org.springframework.security.web.SecurityFilterChain;
////////import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
////////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
////////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
////////
////////@Configuration
////////@EnableWebSecurity
////////public class AuthorizationServerSecurityConfig {
////////
////////    // Chain for SAS endpoints (/oauth2/**, /.well-known/**, /connect/**)
////////    @Bean
////////    @Order(1)
////////    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
////////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
////////
////////        OAuth2AuthorizationServerConfigurer as = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
////////        http.securityMatcher(as.getEndpointsMatcher());
////////
////////        http.exceptionHandling(ex ->
////////                ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login"))
////////        );
////////
////////        as.oidc(Customizer.withDefaults());
////////        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
////////        http.cors(Customizer.withDefaults());
////////        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**"));
////////
////////        return http.build();
////////    }
////////
////////    // Chain for app routes (custom login UI, static assets, admin JSON, etc.)
////////    @Bean
////////    @Order(2)
////////    SecurityFilterChain application(HttpSecurity http, AuthUiProperties uiProps) throws Exception {
////////        var savedHandler = new SavedRequestAwareAuthenticationSuccessHandler();
////////        // Saved request (authorize URL) wins; if none, fall back to configurable default
////////        savedHandler.setDefaultTargetUrl(uiProps.getDefaultSuccessUrl());
////////        savedHandler.setAlwaysUseDefaultTargetUrl(false);
////////
////////        http
////////                .authorizeHttpRequests(reg -> reg
////////                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
////////                        .requestMatchers(
////////                                "/auth/login", "/auth/login/**",
////////                                "/login", "/oauth/login",
////////                                "/auth/csrf",
////////                                "/assets/**", "/css/**", "/js/**", "/images/**",
////////                                "/favicon.ico", "/error", "/actuator/**"
////////                        ).permitAll()
////////                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()
////////                        .requestMatchers("/admin/clients").hasRole("ADMIN")
////////                        .anyRequest().authenticated()
////////                )
////////                .formLogin(form -> form
////////                        .loginPage("/auth/login")
////////                        .loginProcessingUrl("/login") // POST target
////////                        .successHandler(savedHandler)
////////                        .permitAll()
////////                )
////////                .csrf(csrf -> csrf
////////                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////////                        .ignoringRequestMatchers("/connect/register") // keep /login protected!
////////                )
////////                .cors(Customizer.withDefaults());
////////
//////////                .formLogin(form -> form
//////////                        .loginPage("/auth/login")
//////////                        .loginProcessingUrl("/login")
//////////                        .successHandler(savedHandler) // resumes /oauth2/authorize; else default-success-url
//////////                        .permitAll()
//////////                )
//////////                .httpBasic(Customizer.withDefaults())
//////////                .cors(Customizer.withDefaults())
//////////                .csrf(csrf -> csrf
//////////                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//////////                        .ignoringRequestMatchers("/connect/register")
//////////                );
////////
////////        return http.build();
////////    }
////////
////////    @Bean
////////    AuthorizationServerSettings authorizationServerSettings() {
////////        return AuthorizationServerSettings.builder()
////////                .issuer("http://localhost:9000")
////////                .build();
////////    }
////////}
//////
//////package com.example.authorizationserver.config;
//////
//////import org.springframework.context.annotation.Bean;
//////import org.springframework.context.annotation.Configuration;
//////import org.springframework.core.annotation.Order;
//////import org.springframework.http.HttpMethod;
//////import org.springframework.security.config.Customizer;
//////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//////import org.springframework.security.web.SecurityFilterChain;
//////import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
//////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
//////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
//////
//////@Configuration
//////@EnableWebSecurity
//////public class AuthorizationServerSecurityConfig {
//////
//////    // Chain for SAS endpoints (/oauth2/**, /.well-known/**, /connect/**)
//////    @Bean
//////    @Order(1)
//////    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
//////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//////
//////        OAuth2AuthorizationServerConfigurer as = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
//////        http.securityMatcher(as.getEndpointsMatcher());
//////
//////        http.exceptionHandling(ex ->
//////                ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login"))
//////        );
//////
//////        as.oidc(Customizer.withDefaults());
//////        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
//////        http.cors(Customizer.withDefaults());
//////        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**"));
//////
//////        return http.build();
//////    }
//////
//////    // Chain for app routes (custom login UI, static assets, admin JSON, CSRF endpoint, etc.)
//////    @Bean
//////    @Order(2)
//////    SecurityFilterChain application(HttpSecurity http, AuthUiProperties uiProps) throws Exception {
//////        // Saved request (authorize URL) wins; if none, fall back to configured URL
//////        var savedHandler = new SavedRequestAwareAuthenticationSuccessHandler();
//////        savedHandler.setAlwaysUseDefaultTargetUrl(false);
//////        savedHandler.setDefaultTargetUrl(uiProps.getDefaultSuccessUrl()); // e.g. http://localhost:5173/
//////
//////        http
//////                .authorizeHttpRequests(reg -> reg
//////                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
//////
//////                        // Public endpoints and assets
//////                        .requestMatchers(
//////                                "/auth/login", "/auth/login/**",   // your custom login page route (optional)
//////                                "/login", "/oauth/login",          // GET redirects → /auth/login; POST /login is the processing endpoint
//////                                "/auth/csrf",                      // CSRF helper
//////                                "/assets/**", "/css/**", "/js/**", "/images/**",
//////                                "/favicon.ico", "/error", "/actuator/**"
//////                        ).permitAll()
//////
//////                        // DCR (your controller should validate initial token)
//////                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()
//////
//////                        // Admin JSON
//////                        .requestMatchers("/admin/clients").hasRole("ADMIN")
//////
//////                        .anyRequest().authenticated()
//////                )
//////                .formLogin(form -> form
//////                        .loginPage("/auth/login")      // where your login UI lives
//////                        .loginProcessingUrl("/login")  // Spring Security UsernamePasswordAuthenticationFilter
//////                        .successHandler(savedHandler)  // resume saved /oauth2/authorize or fallback to default-success-url
//////                        .permitAll()
//////                )
//////                .httpBasic(Customizer.withDefaults())
//////                .cors(Customizer.withDefaults())
//////                .csrf(csrf -> csrf
//////                        // IMPORTANT: we keep CSRF ON for /login
//////                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//////                        .ignoringRequestMatchers("/connect/register") // leave /login protected!
//////                );
//////
//////        return http.build();
//////    }
//////
//////    @Bean
//////    AuthorizationServerSettings authorizationServerSettings() {
//////        return AuthorizationServerSettings.builder()
//////                .issuer("http://localhost:9000")
//////                .build();
//////    }
//////}
////
////package com.example.authorizationserver.config;
////
////import org.springframework.context.annotation.Bean;
////import org.springframework.context.annotation.Configuration;
////import org.springframework.core.annotation.Order;
////import org.springframework.http.HttpMethod;
////import org.springframework.security.config.Customizer;
////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
////import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
////import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
////import org.springframework.security.web.SecurityFilterChain;
////import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
////import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
////import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
////
////@Configuration
////@EnableWebSecurity
////public class AuthorizationServerSecurityConfig {
////
////    // Chain for SAS endpoints (/oauth2/**, /.well-known/**, /connect/**)
////    @Bean
////    @Order(1)
////    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
////
////        OAuth2AuthorizationServerConfigurer as = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
////        http.securityMatcher(as.getEndpointsMatcher());
////
////        http.exceptionHandling(ex ->
////                ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login"))
////        );
////
////        as.oidc(Customizer.withDefaults());
////        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
////        http.cors(Customizer.withDefaults());
////        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**"));
////
////        return http.build();
////    }
////
////    // Chain for app routes (custom login UI, static assets, admin JSON, CSRF endpoint, etc.)
////    @Bean
////    @Order(2)
////    SecurityFilterChain application(HttpSecurity http, AuthUiProperties uiProps) throws Exception {
////        var savedHandler = new SavedRequestAwareAuthenticationSuccessHandler();
////        savedHandler.setAlwaysUseDefaultTargetUrl(false);
////        savedHandler.setDefaultTargetUrl(uiProps.getDefaultSuccessUrl()); // used only if no saved request
////
////        http
////                .authorizeHttpRequests(reg -> reg
////                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
////                        .requestMatchers(
////                                "/auth/login", "/auth/login/**",
////                                "/login", "/oauth/login",
////                                "/auth/csrf",
////                                "/assets/**", "/css/**", "/js/**", "/images/**",
////                                "/favicon.ico", "/error", "/actuator/**"
////                        ).permitAll()
////                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()
////                        .requestMatchers("/admin/clients").hasRole("ADMIN")
////                        .anyRequest().authenticated()
////                )
////                .formLogin(form -> form
////                        .loginPage("/auth/login")
////                        .loginProcessingUrl("/login")      // POST target for the form
////                        .successHandler(savedHandler)      // resume authorize flow; else default-success-url
////                        .permitAll()
////                )
////                .httpBasic(Customizer.withDefaults())
////                .cors(Customizer.withDefaults())
////                .csrf(csrf -> csrf
////                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////                        .ignoringRequestMatchers("/connect/register")  // keep /login protected!
////                );
////
////        return http.build();
////    }
////
////    @Bean
////    AuthorizationServerSettings authorizationServerSettings() {
////        return AuthorizationServerSettings.builder()
////                .issuer("http://localhost:9000")
////                .build();
////    }
////}
//
//package com.example.authorizationserver.config;
//
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
//import org.springframework.http.HttpMethod;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
//import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//import org.springframework.security.web.savedrequest.SavedRequest;
//
//@Configuration
//public class AuthorizationServerSecurityConfig {
//
//    @Bean
//    @Order(1)
//    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//        OAuth2AuthorizationServerConfigurer as = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
//        http.securityMatcher(as.getEndpointsMatcher());
//        http.exceptionHandling(ex -> ex.authenticationEntryPoint(
//                new org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint("/auth/login")));
//        as.oidc(Customizer.withDefaults());
//        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
//        http.cors(Customizer.withDefaults());
//        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**"));
//        return http.build();
//    }
//
//    @Bean
//    @Order(2)
//    SecurityFilterChain application(HttpSecurity http, AuthUiProperties ui) throws Exception {
//        http
//                .authorizeHttpRequests(reg -> reg
//                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
//                        .requestMatchers(
//                                "/auth/login", "/auth/login/**",
//                                "/login", "/oauth/login",
//                                "/auth/csrf",
//                                "/assets/**", "/css/**", "/js/**", "/images/**",
//                                "/favicon.ico", "/error", "/actuator/**"
//                        ).permitAll()
//                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()
//                        .requestMatchers("/admin/clients").hasRole("ADMIN")
//                        .anyRequest().authenticated()
//                )
//                .formLogin(form -> form
//                        .loginPage("/auth/login")
//                        .loginProcessingUrl("/login")        // POST target
//                        .successHandler(loginSuccessHandler(ui))  // <<< important
//                        .permitAll()
//                )
//                .httpBasic(Customizer.withDefaults())
//                .cors(Customizer.withDefaults())
//                .csrf(csrf -> csrf
//                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                        .ignoringRequestMatchers("/connect/register")   // keep /login protected!
//                );
//
//        return http.build();
//    }
//
//    @Bean
//    AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder().issuer("http://localhost:9000").build();
//    }
//
//    // ----- Custom success handler -----
//    @Bean
//    AuthenticationSuccessHandler loginSuccessHandler(AuthUiProperties ui) {
////        return (HttpServletRequest request, HttpServletResponse response, var authentication) -> {
//        return (var request, var response,  var authentication )->{
//            var cache = new HttpSessionRequestCache();
//            SavedRequest saved = cache.getRequest(request, response);
//
//            // If there was a proper saved request (e.g., /oauth2/authorize?...), go there.
//            if (saved != null) {
//                String target = saved.getRedirectUrl();
//                // Guard against root or error targets that cause 404 loops
//                if (isBogusTarget(target)) {
//                    response.sendRedirect(ui.getDefaultSuccessUrl());
//                } else {
//                    response.sendRedirect(target);
//                }
//                return;
//            }
//
//            // No saved request → fallback to configured default-success-url
//            response.sendRedirect(ui.getDefaultSuccessUrl());
//        };
//    }
//
//    private boolean isBogusTarget(String url) {
//        if (url == null) return true;
//        // normalize trailing slash
//        String lower = url.toLowerCase();
//        // treat root (…:9000/ or just “/”) & error targets as bogus
//        return lower.matches("^https?://[^/]+(:\\d+)?/$") || lower.endsWith("/error") || lower.endsWith("/error?") || lower.endsWith("/error?continue");
//    }
//}

package com.example.authorizationserver.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Configuration
@EnableWebSecurity
public class AuthorizationServerSecurityConfig {

    /**
     * Security chain for Spring Authorization Server endpoints
     * (/oauth2/**, /.well-known/**, /connect/**).
     */
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
        // Apply SAS defaults (authorize/token/jwks/etc)
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        OAuth2AuthorizationServerConfigurer as =
                http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);

        // Make this chain apply only to SAS endpoints
        http.securityMatcher(as.getEndpointsMatcher());

        // If unauthenticated, send to our custom login page instead of whitelabel
        http.exceptionHandling(ex ->
                ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login"))
        );

        // Enable OIDC and resource server (for e.g. token revocation)
        as.oidc(Customizer.withDefaults());
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        // CORS + CSRF (ignore SAS endpoints for CSRF)
        http.cors(Customizer.withDefaults());
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**"));

        return http.build();
    }

    /**
     * Security chain for application endpoints:
     * - custom login UI (/auth/login & static assets)
     * - CSRF helper (/auth/csrf)
     * - admin API (/admin/clients)
     * - your custom DCR (/connect/register) if you expose one
     */
    @Bean
    @Order(2)
    SecurityFilterChain application(HttpSecurity http, AuthUiProperties uiProps) throws Exception {
        http
                .authorizeHttpRequests(reg -> reg
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers(
                                "/auth/login", "/auth/login/**",
                                "/login", "/oauth/login",
                                "/auth/csrf",
                                "/assets/**", "/css/**", "/js/**", "/images/**",
                                "/favicon.ico", "/error", "/actuator/**"
                        ).permitAll()
                        .requestMatchers(HttpMethod.POST, "/connect/register").permitAll()
                        .requestMatchers("/admin/clients").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/auth/login")
                        .loginProcessingUrl("/login")          // POST target from your React login form
                        .successHandler(loginSuccessHandler(uiProps))  // resume saved /oauth2/authorize or fallback
                        .permitAll()
                )
                .httpBasic(Customizer.withDefaults())
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringRequestMatchers("/connect/register")  // keep /login protected by CSRF!
                );

        return http.build();
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9000")
                .build();
    }

    /**
     * Custom success handler:
     * - If a SavedRequest exists (e.g., user was headed to /oauth2/authorize?...),
     *   we redirect there (unless it's bogus like "/" or "/error").
     * - Otherwise we redirect to auth.ui.default-success-url (e.g., http://localhost:5173/).
     */
    @Bean
    AuthenticationSuccessHandler loginSuccessHandler(AuthUiProperties uiProps) {
        return (HttpServletRequest request,
                HttpServletResponse response,
                Authentication authentication) -> {

            HttpSessionRequestCache cache = new HttpSessionRequestCache();
            SavedRequest saved = cache.getRequest(request, response);

            if (saved != null) {
                String target = saved.getRedirectUrl();
                if (isBogusTarget(target)) {
                    response.sendRedirect(uiProps.getDefaultSuccessUrl());
                } else {
                    response.sendRedirect(target);
                }
                return;
            }

            response.sendRedirect(uiProps.getDefaultSuccessUrl());
        };
    }

    private boolean isBogusTarget(String url) {
        if (url == null) return true;
        String lower = url.toLowerCase();

        // root like http://host:port/ or just "/"
        boolean isRoot = lower.matches("^https?://[^/]+(:\\d+)?/$") || "/".equals(lower);

        // error pages (occasionally captured as a "saved" request)
        boolean isError = lower.endsWith("/error") || lower.contains("/error?");

        return isRoot || isError;
    }
}
