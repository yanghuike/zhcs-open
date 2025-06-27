package com.zhcs.open.utils;

import com.zhcs.open.Controller.Result;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;

public class TokenCache {
    private static final ConcurrentHashMap<String, TokenInfo> TOKEN_CACHE = new ConcurrentHashMap<>();
    // Token有效期设置为1小时45分钟（比2小时小，确保在过期前刷新）
    private static final long TOKEN_VALID_MINUTES = 105;

    @Data
    private static class TokenInfo {
        private String token;
        private LocalDateTime expireTime;
        private String userCode;
        private String lastLoginTime;

        public TokenInfo(Result result) {
            this.token = result.getToken();
            this.userCode = result.getUserCode();
            this.lastLoginTime = result.getLastLoginTime();
            this.expireTime = LocalDateTime.now().plusMinutes(TOKEN_VALID_MINUTES);
        }

        public boolean isExpired() {
            return LocalDateTime.now().isAfter(expireTime);
        }
    }

    public static Result getToken(String username) {
        TokenInfo tokenInfo = TOKEN_CACHE.get(username);
        if (tokenInfo != null && !tokenInfo.isExpired()) {
            Result result = new Result();
            result.setToken(tokenInfo.getToken());
            result.setUserCode(tokenInfo.getUserCode());
            result.setUserName(username);
            result.setLastLoginTime(tokenInfo.getLastLoginTime());
            return result;
        }
        return null;
    }

    public static void setToken(String username, Result result) {
        TOKEN_CACHE.put(username, new TokenInfo(result));
    }

    public static void removeToken(String username) {
        TOKEN_CACHE.remove(username);
    }
} 