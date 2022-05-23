package com.github.monee1988.config;

import com.github.monee1988.shiro.CustomSessionManager;
import com.github.monee1988.shiro.NoSessionDefaultSubjectFactory;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.mgt.SubjectDAO;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroWebConfiguration;
import org.apache.shiro.web.filter.authc.BearerHttpAuthenticationFilter;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
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
@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class ShiroNoSessionConfiguration extends AbstractShiroConfiguration{

    /**
     * Subject factory subject factory.
     * 告诉shiro不创建内置的session
     * @see ShiroWebConfiguration#subjectFactory()
     * @return the subject factory
     */
    @Bean
    @ConditionalOnProperty(name = "shiro.web.session.disabled", havingValue = "true")
    public SubjectFactory subjectFactory(){
        return new NoSessionDefaultSubjectFactory();
    }

    /**
     * 关闭 ShiroDAO 功能
     * @see ShiroWebConfiguration#subjectDAO()
     * @return subject dao
     */
    @Bean
    @ConditionalOnProperty(name = "shiro.web.session.disabled", havingValue = "true")
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
    @ConditionalOnProperty(name = "shiro.web.session.disabled", havingValue = "true")
    public DefaultWebSessionManager sessionManager(){

        DefaultWebSessionManager sessionManager = new CustomSessionManager();
        sessionManager.setSessionValidationSchedulerEnabled(true);
        sessionManager.setSessionIdUrlRewritingEnabled(false);
        sessionManager.setSessionValidationInterval(DefaultWebSessionManager.DEFAULT_SESSION_VALIDATION_INTERVAL);

        return sessionManager;
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
    @ConditionalOnMissingBean
    @Override
    public CacheManager cacheManager() {
        return super.cacheManager();
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
