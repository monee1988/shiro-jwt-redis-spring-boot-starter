package com.github.monee1988.shiro;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The type Shiro filter chain properties.
 *
 * @author monee1988
 * @version 1.0
 * @date 2022 -05-25 18:10
 */
@ConfigurationProperties(prefix = "shiro")
public class ShiroFilterChainProperties {

    /**
     * 登陆URL
     */
    private String loginUrl = "/login";

    /**
     * token过期URL
     */
    private String tokenExpiredUrl="/tokenExpired";

    /**
     * 不支持的token类型URL
     */
    private String unsupportedTokenUrl="/unsupportedToken";

    /**
     * 登出URL
     */
    private String logoutUrl="/logout";

    /**
     * Gets login url.
     *
     * @return the login url
     */
    public String getLoginUrl() {
        return loginUrl;
    }

    /**
     * Sets login url.
     *
     * @param loginUrl the login url
     */
    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    /**
     * Gets token expired url.
     *
     * @return the token expired url
     */
    public String getTokenExpiredUrl() {
        return tokenExpiredUrl;
    }

    /**
     * Sets token expired url.
     *
     * @param tokenExpiredUrl the token expired url
     */
    public void setTokenExpiredUrl(String tokenExpiredUrl) {
        this.tokenExpiredUrl = tokenExpiredUrl;
    }

    /**
     * Gets unsupported token url.
     *
     * @return the unsupported token url
     */
    public String getUnsupportedTokenUrl() {
        return unsupportedTokenUrl;
    }

    /**
     * Sets unsupported token url.
     *
     * @param unsupportedTokenUrl the unsupported token url
     */
    public void setUnsupportedTokenUrl(String unsupportedTokenUrl) {
        this.unsupportedTokenUrl = unsupportedTokenUrl;
    }

    /**
     * Gets logout url.
     *
     * @return the logout url
     */
    public String getLogoutUrl() {
        return logoutUrl;
    }

    /**
     * Sets logout url.
     *
     * @param logoutUrl the logout url
     */
    public void setLogoutUrl(String logoutUrl) {
        this.logoutUrl = logoutUrl;
    }
}
