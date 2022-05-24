package com.github.monee1988.config;

import com.github.monee1988.jwt.JwtUtils;
import com.github.monee1988.shiro.CustomSessionManager;
import com.github.monee1988.shiro.NoSessionDefaultSubjectFactory;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.mgt.SubjectDAO;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroWebConfiguration;
import org.apache.shiro.web.filter.authc.BearerHttpAuthenticationFilter;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.crazycake.shiro.RedisCacheManager;
import org.crazycake.shiro.RedisSessionDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author monee1988
 * @version 1.0
 * @date 2022-05-23 20:26
 */
@Configuration()
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class ShiroNoSessionConfiguration extends AbstractShiroConfiguration{


    //指定一个token过期时间（毫秒） //20分钟
    @Value("#{ @environment['shiro.jwt.expireTime'] ?:  1200000 }")
    private long expireTime;

    @Value("#{ @environment['shiro.jwt.tokenSecret'] ?: 'monee1988' }")
    private String tokenSecret;


    private RedisSessionDAO redisSessionDAO;

    private RedisCacheManager redisCacheManager;

    @Autowired(required = false)
    public void setRedisSessionDAO(RedisSessionDAO redisSessionDAO) {
        this.redisSessionDAO = redisSessionDAO;
    }

    @Autowired(required = false)
    public void setRedisCacheManager(RedisCacheManager redisCacheManager) {
        this.redisCacheManager = redisCacheManager;
    }

    /**
     * Subject factory subject factory.
     * 告诉shiro不创建内置的session
     * @see ShiroWebConfiguration#subjectFactory()
     * @return the subject factory
     */
    @Bean
    @ConditionalOnProperty(name = "shiro.web.session.enabled", havingValue = "false")
    public SubjectFactory subjectFactory(){
        return new NoSessionDefaultSubjectFactory();
    }

    @Bean
    public JwtUtils jwtUtils(){

        return new JwtUtils(expireTime,tokenSecret);
    }


    /**
     * 关闭 ShiroDAO 功能
     * @see ShiroWebConfiguration#subjectDAO()
     * @return subject dao
     */
    @Bean
    @ConditionalOnProperty(name = "shiro.web.session.enabled", havingValue = "false")
    public SubjectDAO subjectDAO() {
        DefaultSubjectDAO subjectDAO = new DefaultSubjectDAO();
        DefaultSessionStorageEvaluator defaultSessionStorageEvaluator = new DefaultSessionStorageEvaluator();
        // 不需要将 Shiro Session 中的东西存到任何地方（包括 Http Session 中）
        defaultSessionStorageEvaluator.setSessionStorageEnabled(false);
        subjectDAO.setSessionStorageEvaluator(defaultSessionStorageEvaluator);
        return subjectDAO;
    }

    /**
     * 会话管理器
     * 管理着应用中所有Subject的会话，包括会话的创建、维护、删除、失效、验证等工作
     * @see ShiroWebConfiguration#sessionManager()
     * @return SessionManager default web session manager
     */
    @Bean
    @ConditionalOnProperty(name = "shiro.web.session.enabled", havingValue = "true")
    public DefaultWebSessionManager sessionManager(){
        DefaultWebSessionManager sessionManager = new CustomSessionManager();
        sessionManager.setSessionDAO(sessionDAO());
        sessionManager.setSessionValidationSchedulerEnabled(true);
        sessionManager.setSessionIdUrlRewritingEnabled(false);
        sessionManager.setSessionValidationInterval(DefaultWebSessionManager.DEFAULT_SESSION_VALIDATION_INTERVAL);
        return sessionManager;

    }

    @Bean
    @ConditionalOnProperty(name = "shiro.web.session.enabled", havingValue = "true")
    public SessionDAO sessionDAO() {
        if(redisSessionDAO!=null){
            return redisSessionDAO;
        }
        return new EnterpriseCacheSessionDAO();
    }

    @Bean
    @ConditionalOnProperty(name = {"shiro.cache.enabled"},matchIfMissing = true)
    @Override
    public CacheManager cacheManager() {
        if(redisCacheManager!=null){
            return redisCacheManager;
        }
        return super.cacheManager();
    }

    @Bean
    @ConditionalOnMissingBean
    @Override
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        return super.shiroFilterChainDefinition();
    }

    @Bean
    @ConditionalOnMissingBean
    @Override
    public BearerHttpAuthenticationFilter bearerHttpAuthenticationFilter() {
        return super.bearerHttpAuthenticationFilter();
    }

    @Bean
    @Override
    public FilterRegistrationBean registration(BearerHttpAuthenticationFilter filter) {
        return super.registration(filter);
    }

    @Bean
    @Override
    public Authorizer authorizer() {
        return super.authorizer();
    }

    @Bean
    @ConditionalOnMissingBean
    @Override
    public Authenticator authenticator() {
        return super.authenticator();
    }

}
