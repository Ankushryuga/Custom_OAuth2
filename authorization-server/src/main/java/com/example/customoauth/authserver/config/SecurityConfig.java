package com.example.customoauth.authserver.config;
import org.springframework.beans.factory.annotation.Value; import org.springframework.context.annotation.Bean; import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer; import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User; import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder; import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager; import org.springframework.security.web.SecurityFilterChain;
@Configuration public class SecurityConfig {
  @Value("${auth.admin.user:admin}") private String adminUser; @Value("${auth.admin.password:admin123}") private String adminPassword;
  @Bean public SecurityFilterChain appSecurity(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(a->a.requestMatchers("/actuator/**","/.well-known/**").permitAll().anyRequest().authenticated())
      .formLogin(Customizer.withDefaults()).httpBasic(Customizer.withDefaults()); return http.build(); }
  @Bean UserDetailsService users(PasswordEncoder pe){ return new InMemoryUserDetailsManager(
      User.withUsername(adminUser).password(pe.encode(adminPassword)).roles("ADMIN").build(),
      User.withUsername("user").password(pe.encode("password")).roles("USER").build()); }
  @Bean PasswordEncoder passwordEncoder(){ return new BCryptPasswordEncoder(); }
}
