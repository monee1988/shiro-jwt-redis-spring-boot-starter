package com.github.monee1988.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author monee1988
 * @version 1.0
 * @date 2022-05-25 17:51
 */
@ConfigurationProperties(prefix = "shiro.jwt")
public class JwtUtilProperties {

    private long expireTime;

    private String tokenSecret;

    public long getExpireTime() {
        return expireTime;
    }

    public void setExpireTime(long expireTime) {
        this.expireTime = expireTime;
    }

    public String getTokenSecret() {
        return tokenSecret;
    }

    public void setTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }
}
