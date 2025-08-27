//package com.example.customoauth.client.config;
//import org.springframework.context.annotation.Bean; import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.Customizer; import org.springframework.security.config.annotation.web.builders.HttpSecurity; import org.springframework.security.web.SecurityFilterChain;
//@Configuration public class SecurityConfig {
//  @Bean SecurityFilterChain web(HttpSecurity http) throws Exception {
//    http.authorizeHttpRequests(a->a.requestMatchers("/", "/actuator/**").permitAll().anyRequest().authenticated())
//      .oauth2Login(Customizer.withDefaults()).logout(l->l.logoutSuccessUrl("/").permitAll()); return http.build(); }
//}



package com.example.customoauth.client.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.AuthenticationException;     // <-- important
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

@Configuration
public class SecurityConfig {
  private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

  @Bean
  SecurityFilterChain web(HttpSecurity http) throws Exception {
    AuthenticationFailureHandler logFailure =
            (HttpServletRequest req, HttpServletResponse res, AuthenticationException ex) -> {
              log.error("OAuth2 login FAILED: {} - {}", ex.getClass().getSimpleName(), ex.getMessage(), ex);
              res.setStatus(400);
              res.setContentType("text/plain");
              res.getWriter().println("OAuth2 login FAILED: " + ex.getMessage());
            };

//    http
//            .authorizeHttpRequests(a -> a
//                    .requestMatchers("/", "/actuator/**").permitAll()
//                    .anyRequest().authenticated())
//            .oauth2Login(o -> o.failureHandler(logFailure))
//            .logout(l -> l.logoutSuccessUrl("/").permitAll());


      http
              .authorizeHttpRequests(a -> a
                      .requestMatchers("/", "/actuator/**").permitAll()
                      .anyRequest().authenticated())
              .oauth2Login(o -> o
                      .defaultSuccessUrl("/me", true) // 👈 always go to /me after successful login
              )
              .logout(l -> l.logoutSuccessUrl("/").permitAll());


      return http.build();
  }
}
