//////// authorization-server/src/main/java/com/example/authorizationserver/web/CsrfController.java
//////package com.example.authorizationserver.web;
//////
//////import org.springframework.security.web.csrf.CsrfToken;
//////import org.springframework.web.bind.annotation.GetMapping;
//////import org.springframework.web.bind.annotation.RestController;
//////
//////import java.util.Map;
//////
//////@RestController
//////public class CsrfController {
//////
//////    @GetMapping("/auth/csrf")
//////    public Map<String, String> csrf(CsrfToken token) {
//////        // Accessing it ensures CookieCsrfTokenRepository also writes XSRF-TOKEN cookie.
//////        return Map.of("headerName", token.getHeaderName(),
//////                "parameterName", token.getParameterName(),
//////                "token", token.getToken());
//////    }
//////}
////// authorization-server/src/main/java/com/example/authorizationserver/web/CsrfController.java
////package com.example.authorizationserver.web;
////
////import org.springframework.http.ResponseEntity;
////import org.springframework.security.web.csrf.CsrfToken;
////import org.springframework.web.bind.annotation.GetMapping;
////import org.springframework.web.bind.annotation.RestController;
////import java.util.Map;
////
////@RestController
////public class CsrfController {
////
////    @GetMapping("/auth/csrf")
////    public ResponseEntity<Map<String, String>> csrf(CsrfToken token) {
////        // Accessing CsrfToken makes CookieCsrfTokenRepository write XSRF-TOKEN cookie
////        return ResponseEntity.ok(Map.of(
////                "headerName", token.getHeaderName(),      // usually "X-XSRF-TOKEN"
////                "parameterName", token.getParameterName(),// "_csrf"
////                "token", token.getToken()
////        ));
////    }
////}
//
//package com.example.authorizationserver.web;
//
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.web.csrf.CsrfToken;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RestController;
//import java.util.Map;
//
//@RestController
//public class CsrfController {
//
//    @GetMapping("/auth/csrf")
//    public ResponseEntity<Map<String, String>> csrf(CsrfToken token) {
//        // Accessing CsrfToken makes CookieCsrfTokenRepository write XSRF-TOKEN cookie
//        return ResponseEntity.ok(Map.of(
//                "headerName", token.getHeaderName(),       // usually "X-XSRF-TOKEN"
//                "parameterName", token.getParameterName(), // "_csrf"
//                "token", token.getToken()
//        ));
//    }
//}

package com.example.authorizationserver.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class CsrfController {
    @GetMapping("/auth/csrf")
    public ResponseEntity<Map<String, String>> csrf(CsrfToken token) {
        return ResponseEntity.ok(Map.of(
                "headerName", token.getHeaderName(),       // "X-XSRF-TOKEN"
                "parameterName", token.getParameterName(), // "_csrf"
                "token", token.getToken()
        ));
    }
}
