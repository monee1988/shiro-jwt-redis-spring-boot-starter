package com.github.monee1988.config;

import com.github.monee1988.jwt.JwtUtil;
import com.github.monee1988.jwt.JwtUtilProperties;
import com.github.monee1988.jwt.impl.JwtUtilImpl;
import com.github.monee1988.shiro.CustomSessionManager;
import com.github.monee1988.shiro.NoSessionDefaultSubjectFactory;
import com.github.monee1988.shiro.ShiroFilterChainProperties;
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
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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
@EnableConfigurationProperties({JwtUtilProperties.class,ShiroFilterChainProperties.class})
public class ShiroNoSessionAutoConfiguration extends AbstractShiroConfiguration{

    private JwtUtilProperties jwtUtilProperties;

    private ShiroFilterChainProperties shiroFilterChainProperties;

    private RedisSessionDAO redisSessionDAO;

    private RedisCacheManager redisCacheManager;

    /**
     * Subject factory subject factory.
     * 告诉shiro不创建内置的session
     * @see ShiroWebConfiguration#subjectFactory()
     * @return the subject factory
     */
    @Bean
    @ConditionalOnProperty(name = "shiro.web.session.enabled", havingValue = "false")
    @ConditionalOnMissingBean
    public SubjectFactory subjectFactory(){
        return new NoSessionDefaultSubjectFactory();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtUtil jwtUtil(){

        return new JwtUtilImpl(jwtUtilProperties.getExpireTime(),jwtUtilProperties.getTokenSecret());
    }

    /**
     * 关闭 ShiroDAO 功能
     * @see ShiroWebConfiguration#subjectDAO()
     * @return subject dao
     */
    @Bean
    @ConditionalOnProperty(name = "shiro.web.session.enabled", havingValue = "false")
    @ConditionalOnMissingBean
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
    @ConditionalOnMissingBean
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
    @ConditionalOnMissingBean
    public SessionDAO sessionDAO() {
        if(redisSessionDAO!=null){
            return redisSessionDAO;
        }
        return new EnterpriseCacheSessionDAO();
    }

    @Bean
    @ConditionalOnProperty(name = {"shiro.cache.enabled"},matchIfMissing = true)
    @ConditionalOnMissingBean
    @Override
    public CacheManager cacheManager() {
        if(redisCacheManager!=null){
            return redisCacheManager;
        }
        return super.cacheManager();
    }

    @Override
    public ShiroFilterChainProperties getFilterChainProperties() {
        return shiroFilterChainProperties;
    }

    @Bean
    @ConditionalOnMissingBean
    @Override
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        return super.shiroFilterChainDefinition();
    }

    @Override
    @Bean
    public JwtUtilImpl getJwtUtils() {
        return new JwtUtilImpl(jwtUtilProperties.getExpireTime(), jwtUtilProperties.getTokenSecret());
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

    @Autowired(required = false)
    public void setRedisSessionDAO(RedisSessionDAO redisSessionDAO) {
        this.redisSessionDAO = redisSessionDAO;
    }

    @Autowired(required = false)
    public void setRedisCacheManager(RedisCacheManager redisCacheManager) {
        this.redisCacheManager = redisCacheManager;
    }
    @Autowired
    public void setJwtUtilProperties(JwtUtilProperties jwtUtilProperties) {
        this.jwtUtilProperties = jwtUtilProperties;
    }
    @Autowired
    public void setShiroFilterChainProperties(ShiroFilterChainProperties shiroFilterChainProperties) {
        this.shiroFilterChainProperties = shiroFilterChainProperties;
    }

}
