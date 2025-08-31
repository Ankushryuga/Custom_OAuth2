// authorization-server/src/main/java/com/example/authorizationserver/dcr/DcrDtos.java
package com.example.authorizationserver.dcr;

import java.util.List;

public class DcrDtos {
    // RFC 7591-ish request (subset)
    public static class ClientRegistrationRequest {
        public String client_name;
        public List<String> redirect_uris;
        public List<String> grant_types;          // e.g., authorization_code, refresh_token
        public List<String> response_types;       // e.g., code
        public String scope;                      // space-delimited
        public String token_endpoint_auth_method; // "client_secret_basic" or "none" (public)
    }

    // RFC-style response (subset)
    public static class ClientRegistrationResponse {
        public String client_id;
        public String client_secret; // not present for public clients
        public long client_id_issued_at;
        public long client_secret_expires_at; // 0 = does not expire
        public List<String> redirect_uris;
        public List<String> grant_types;
        public List<String> response_types;
        public String scope;
        public String token_endpoint_auth_method;
    }
}
