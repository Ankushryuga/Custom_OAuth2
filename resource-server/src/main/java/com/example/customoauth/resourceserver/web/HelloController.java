//package com.example.customoauth.resourceserver.web;
//import org.springframework.web.bind.annotation.GetMapping; import org.springframework.web.bind.annotation.RestController; import java.util.Map;
//@RestController public class HelloController {
//  @GetMapping("/") public String home(){ return "Resource Server is up. Protected API at /api/hello"; }
//  @GetMapping("/api/hello") public Map<String,Object> hello(){ return Map.of("message","Hello from Resource Server","status","ok"); }
//}

//package com.example.customoauth.resourceserver.web;
//
//import org.springframework.http.MediaType;
//import org.springframework.security.core.annotation.AuthenticationPrincipal;
//import org.springframework.security.oauth2.jwt.Jwt;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//import java.util.Map;
//
//@RestController
//public class HelloController {
//
//  @GetMapping(value = "/", produces = MediaType.TEXT_PLAIN_VALUE)
//  public String index() {
//    return "Resource Server is up. Protected API at /api/hello";
//  }
//
//  @GetMapping(value = "/api/hello", produces = MediaType.APPLICATION_JSON_VALUE)
//  public Map<String, Object> hello(@AuthenticationPrincipal Jwt jwt) {
//    return Map.of(
//            "message", "Hello from Resource Server",
//            "status", "ok",
//            "sub", jwt.getSubject(),
//            "scopes", jwt.getClaimAsString("scope")
//    );
//  }
//}


//package com.example.customoauth.resourceserver.web;
//
//import org.springframework.http.MediaType;
//import org.springframework.security.core.annotation.AuthenticationPrincipal;
//import org.springframework.security.oauth2.jwt.Jwt;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//import java.util.Map;
//
//@RestController
//public class HelloController {
//
//  @GetMapping(value = "/", produces = MediaType.TEXT_PLAIN_VALUE)
//  public String index() {
//    return "Resource Server is up. Protected API at /api/hello";
//  }
//
//  @GetMapping(value = "/api/hello", produces = MediaType.APPLICATION_JSON_VALUE)
//  public Map<String, Object> hello(@AuthenticationPrincipal Jwt jwt) {
//    return Map.of(
//            "message", "Hello from Resource Server",
//            "status", "ok",
//            "sub", jwt.getSubject(),
//            "scope", jwt.getClaimAsString("scope")
//    );
//  }
//}


package com.example.customoauth.resourceserver.web;

import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class HelloController {

  @GetMapping(value = "/", produces = MediaType.TEXT_PLAIN_VALUE)
  public String index() {
    return "Resource Server is up. Protected API at /api/hello";
  }

  @GetMapping(value = "/api/hello", produces = MediaType.APPLICATION_JSON_VALUE)
  public Map<String, Object> hello(@AuthenticationPrincipal Jwt jwt) {
    return Map.of(
            "message", "Hello from Resource Server",
            "status", "ok",
            "sub", jwt.getSubject(),
            "scope", jwt.getClaimAsString("scope")
    );
  }
}
