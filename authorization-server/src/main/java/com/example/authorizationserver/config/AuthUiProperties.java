//////// authorization-server/src/main/java/com/example/authorizationserver/config/AuthUiProperties.java
//////package com.example.authorizationserver.config;
//////
//////import org.springframework.boot.context.properties.ConfigurationProperties;
//////
//////import java.util.List;
//////
//////@ConfigurationProperties(prefix = "auth.ui")
//////public class AuthUiProperties {
//////    /**
//////     * Fallback target when there is no saved request after login.
//////     * Defaults to "/" if not set.
//////     */
//////    private String defaultSuccessUrl = "/";
//////
//////    /**
//////     * If the saved request URL contains any of these fragments,
//////     * ignore it and use defaultSuccessUrl instead.
//////     */
//////    private List<String> ignoreSavedRequestContains = List.of("/auth/csrf", "/oauth/login");
//////
//////    public String getDefaultSuccessUrl() { return defaultSuccessUrl; }
//////    public void setDefaultSuccessUrl(String defaultSuccessUrl) { this.defaultSuccessUrl = defaultSuccessUrl; }
//////
//////    public List<String> getIgnoreSavedRequestContains() { return ignoreSavedRequestContains; }
//////    public void setIgnoreSavedRequestContains(List<String> ignoreSavedRequestContains) {
//////        this.ignoreSavedRequestContains = ignoreSavedRequestContains;
//////    }
//////}
////
////package com.example.authorizationserver.config;
////
////import org.springframework.boot.context.properties.ConfigurationProperties;
////
////@ConfigurationProperties(prefix = "auth.ui")
////public class AuthUiProperties {
////
////    /**
////     * Fallback target when there is no saved /oauth2/authorize request after login.
////     * Keep this configurable so you don't hard-code any client URL in code.
////     */
////    private String defaultSuccessUrl = "/";
////
////    public String getDefaultSuccessUrl() {
////        return defaultSuccessUrl;
////    }
////
////    public void setDefaultSuccessUrl(String defaultSuccessUrl) {
////        this.defaultSuccessUrl = defaultSuccessUrl;
////    }
////}
//
//package com.example.authorizationserver.config;
//
//import org.springframework.boot.context.properties.ConfigurationProperties;
//
//@ConfigurationProperties(prefix = "auth.ui")
//public class AuthUiProperties {
//    private String defaultSuccessUrl = "/";
//
//    public String getDefaultSuccessUrl() { return defaultSuccessUrl; }
//    public void setDefaultSuccessUrl(String defaultSuccessUrl) { this.defaultSuccessUrl = defaultSuccessUrl; }
//}

package com.example.authorizationserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.ui")
public class AuthUiProperties {
    private String defaultSuccessUrl = "/";

    public String getDefaultSuccessUrl() { return defaultSuccessUrl; }
    public void setDefaultSuccessUrl(String defaultSuccessUrl) { this.defaultSuccessUrl = defaultSuccessUrl; }
}
