// authorization-server/src/main/java/com/example/authorizationserver/dcr/DcrProperties.java
package com.example.authorizationserver.dcr;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.dcr")
public class DcrProperties {
    private String initialToken = "";
    private boolean requireInitialToken = true;

    public String getInitialToken() { return initialToken; }
    public void setInitialToken(String initialToken) { this.initialToken = initialToken; }
    public boolean isRequireInitialToken() { return requireInitialToken; }
    public void setRequireInitialToken(boolean requireInitialToken) { this.requireInitialToken = requireInitialToken; }
}
