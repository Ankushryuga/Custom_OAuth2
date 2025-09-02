////////////// authorization-server/src/main/java/com/example/authorizationserver/config/WebMvcConfig.java
////////////package com.example.authorizationserver.config;
////////////
////////////import org.springframework.context.annotation.Configuration;
////////////import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
////////////import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
////////////
////////////@Configuration
////////////public class WebMvcConfig implements WebMvcConfigurer {
////////////    @Override
////////////    public void addViewControllers(ViewControllerRegistry r) {
////////////        r.addViewController("/auth/login").setViewName("forward:/auth/login/index.html");
////////////        r.addViewController("/login").setViewName("redirect:/auth/login");
////////////        // NEW: catch the stray path you’re seeing in logs
////////////        r.addViewController("/oauth/login").setViewName("redirect:/auth/login");
//////////////        r.addViewController("/").setViewName("redirect:/auth/login");
////////////        r.addViewController("/").setViewName("forward:/auth/login/index.html");
////////////
////////////
////////////    }
////////////}
//////////
//////////// authorization-server/src/main/java/com/example/authorizationserver/config/WebMvcConfig.java
//////////package com.example.authorizationserver.config;
//////////
//////////import org.springframework.context.annotation.Configuration;
//////////import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
//////////import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
//////////
//////////@Configuration
//////////public class WebMvcConfig implements WebMvcConfigurer {
//////////    @Override
//////////    public void addViewControllers(ViewControllerRegistry r) {
//////////        // Your built React login lives here:
//////////        r.addViewController("/auth/login").setViewName("forward:/auth/login/index.html");
//////////
//////////        // Friendly redirects to the custom login page
//////////        r.addViewController("/login").setViewName("redirect:/auth/login");
//////////        r.addViewController("/oauth/login").setViewName("redirect:/auth/login");
//////////
//////////        // Neutral landing page so "/" doesn't 404 after an ad hoc login
//////////        r.addViewController("/landing").setViewName("forward:/landing/index.html");
//////////
//////////        // If you want "/" to show the landing page (optional but handy):
//////////        r.addViewController("/").setViewName("forward:/landing/index.html");
//////////    }
//////////}
////////
////////package com.example.authorizationserver.config;
////////
////////import org.springframework.context.annotation.Configuration;
////////import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
////////import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
////////
////////@Configuration
////////public class WebMvcConfig implements WebMvcConfigurer {
////////    @Override
////////    public void addViewControllers(ViewControllerRegistry r) {
////////        // Serve your built React login at /auth/login (static file below)
////////        r.addViewController("/auth/login").setViewName("forward:/auth/login/index.html");
////////
////////        // Friendly aliases to the custom login page
////////        r.addViewController("/login").setViewName("redirect:/auth/login");
////////        r.addViewController("/oauth/login").setViewName("redirect:/auth/login");
////////
////////        // Neutral landing page so "/" isn't an error when there is no saved request
////////        r.addViewController("/landing").setViewName("forward:/landing/index.html");
////////
////////        // Optional but recommended: land "/" on the neutral page (NOT the login UI)
////////        r.addViewController("/").setViewName("forward:/landing/index.html");
////////    }
////////}
//////
//////
//////package com.example.authorizationserver.config;
//////
//////import org.springframework.context.annotation.Configuration;
//////import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
//////import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
//////
//////@Configuration
//////public class WebMvcConfig implements WebMvcConfigurer {
//////    @Override
//////    public void addViewControllers(ViewControllerRegistry r) {
//////        // Serve your built React login UI at /auth/login
//////        r.addViewController("/auth/login").setViewName("forward:/auth/login/index.html");
//////
//////        // Friendly aliases → custom login UI
//////        r.addViewController("/login").setViewName("redirect:/auth/login");
//////        r.addViewController("/oauth/login").setViewName("redirect:/auth/login");
//////
//////        // NOTE: We do NOT forward "/" → anything here (avoid 404 loops if missing).
//////        // If you still want a local landing page, you can add one:
//////        // r.addViewController("/landing").setViewName("forward:/landing/index.html");
//////        // r.addViewController("/").setViewName("forward:/landing/index.html");
//////    }
//////}
////
////
////package com.example.authorizationserver.config;
////
////import org.springframework.context.annotation.Configuration;
////import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
////import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
////
////@Configuration
////public class WebMvcConfig implements WebMvcConfigurer {
////    @Override
////    public void addViewControllers(ViewControllerRegistry r) {
////        // Only needed if you ship a React login bundle inside the AS
////        r.addViewController("/auth/login").setViewName("forward:/auth/login/index.html");
////
////        // Friendly aliases:
////        r.addViewController("/login").setViewName("redirect:/auth/login");
////        r.addViewController("/oauth/login").setViewName("redirect:/auth/login");
////
////        // Do NOT forward "/" unless you also ship a landing page
////        // r.addViewController("/").setViewName("forward:/landing/index.html");
////    }
////}
//
//package com.example.authorizationserver.config;
//
//import org.springframework.context.annotation.Configuration;
//import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
//import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
//
//@Configuration
//public class WebMvcConfig implements WebMvcConfigurer {
//    @Override
//    public void addViewControllers(ViewControllerRegistry r) {
//        // Serve your built React login UI at /auth/login
//        r.addViewController("/auth/login").setViewName("forward:/auth/login/index.html");
//        // Friendly aliases
//        r.addViewController("/login").setViewName("redirect:/auth/login");
//        r.addViewController("/oauth/login").setViewName("redirect:/auth/login");
//        // Do not forward "/" unless you ship a local landing page
//    }
//}

package com.example.authorizationserver.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    @Override
    public void addViewControllers(ViewControllerRegistry r) {
        // Serve your built React login UI at /auth/login
        r.addViewController("/auth/login").setViewName("forward:/auth/login/index.html");
        // Friendly aliases
        r.addViewController("/login").setViewName("redirect:/auth/login");
        r.addViewController("/oauth/login").setViewName("redirect:/auth/login");

        // OPTIONAL safety: if someone hits the root, send them to login page
        // remove if you prefer a landing page or API-only behavior
        r.addViewController("/").setViewName("redirect:/auth/login");
    }
}
