////// authorization-server/src/main/java/com/example/authorizationserver/config/CorsConfig.java
////package com.example.authorizationserver.config;
////
////import org.springframework.context.annotation.Bean;
////import org.springframework.context.annotation.Configuration;
////import org.springframework.web.cors.CorsConfiguration;
////import org.springframework.web.cors.CorsConfigurationSource;
////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
////
////import java.util.List;
////
////@Configuration
////public class CorsConfig {
////
////    @Bean
////    public CorsConfigurationSource corsConfigurationSource() {
////        CorsConfiguration cfg = new CorsConfiguration();
////        // DEV: allow patterns; in prod, restrict to allowed origins or tenant origins
////        cfg.setAllowedOriginPatterns(List.of("http://localhost:*", "http://127.0.0.1:*"));
////        cfg.setAllowedMethods(List.of("GET","POST","OPTIONS","PUT","DELETE"));
////        cfg.setAllowedHeaders(List.of("Content-Type","X-XSRF-TOKEN","Authorization","Accept"));
////        cfg.setAllowCredentials(true);
////        cfg.setMaxAge(3600L);
////
////        UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
////        src.registerCorsConfiguration("/**", cfg);
////        return src;
////    }
////}
//
//package com.example.authorizationserver.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.web.cors.CorsConfiguration;
//import org.springframework.web.cors.CorsConfigurationSource;
//import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//
//import java.util.List;
//
//@Configuration
//public class CorsConfig {
//
//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration cfg = new CorsConfiguration();
//
//        // DEV convenience: allow local origins; in PROD restrict to known origins or tenant list
//        cfg.setAllowedOriginPatterns(List.of("http://localhost:*", "http://127.0.0.1:*"));
//        cfg.setAllowedMethods(List.of("GET","POST","OPTIONS","PUT","DELETE"));
//        cfg.setAllowedHeaders(List.of("Content-Type","X-XSRF-TOKEN","Authorization","Accept"));
//        cfg.setAllowCredentials(true);
//        cfg.setMaxAge(3600L);
//
//        UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
//        src.registerCorsConfiguration("/**", cfg);
//        return src;
//    }
//}
package com.example.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOriginPatterns(List.of("http://localhost:*", "http://127.0.0.1:*"));
        cfg.setAllowedMethods(List.of("GET","POST","OPTIONS","PUT","DELETE"));
        cfg.setAllowedHeaders(List.of("Content-Type","X-XSRF-TOKEN","Authorization","Accept"));
        cfg.setAllowCredentials(true);
        cfg.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
        src.registerCorsConfiguration("/**", cfg);
        return src;
    }
}
