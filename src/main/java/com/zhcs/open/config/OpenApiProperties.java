package com.zhcs.open.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "zhcs.open")
public class OpenApiProperties {
    
    private ServerConfig server;
    private AuthConfig auth;
    private ResourceServerConfig resourceServer;
    private ResourceConfig resource;
    private LoginConfig login;
    
    @Data
    public static class ServerConfig {
        private String ip;
        private String port;
        private String prefix;
    }
    
    @Data
    public static class AuthConfig {
        private String realm;
        private String encryptType;
        private String url;
        private String resourceUrl;
    }

    @Data
    public static class ResourceServerConfig {
        private String ip;
        private String port;
        private String prefix;
    }

    @Data
    public static class ResourceConfig {
        private String networkStatusUrl;
        private String districtUrl;
        private String deptUrl;
        private String algorithmUrl;
        private DefaultAuth defaultAuth;
    }

    @Data
    public static class DefaultAuth {
        private String username;
        private String password;
        private String roleType;
    }

    @Data
    public static class LoginConfig {
        private String url;
        private String username;
        private String password;
        private String clientType;
    }
} 