package com.github.monee1988.config;

import com.github.monee1988.jwt.JwtUtils;
import com.github.monee1988.shiro.UserModularRealmAuthenticator;
import com.github.monee1988.shiro.filter.ShiroAuthenticationFilter;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authc.pam.FirstSuccessfulStrategy;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroWebConfiguration;
import org.apache.shiro.web.filter.authc.BearerHttpAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import javax.annotation.Resource;
import java.util.List;

/**
 * @author monee1988
 * @version 1.0
 * @date 2022-05-23 20:26
 */
public class AbstractShiroConfiguration {

    //登陆URL
    @Value("#{ @environment['shiro.loginUrl'] ?: '/login' }")
    protected String loginUrl;

    //token过期URL
    @Value("#{ @environment['shiro.tokenExpired'] ?: '/tokenExpired' }")
    protected String tokenExpiredUrl;

    //不支持的token类型URL
    @Value("#{ @environment['shiro.unsupportedToken'] ?: '/unsupportedToken' }")
    protected String unsupportedTokenUrl;

    //登出URL
    @Value("#{ @environment['shiro.logout'] ?: '/logout' }")
    protected String logoutUrl;

    public ShiroFilterChainDefinition shiroFilterChainDefinition() {

        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        // 哪些请求可以匿名访问
        chainDefinition.addPathDefinition(loginUrl,"anon");             //登陆接口
        chainDefinition.addPathDefinition(tokenExpiredUrl,"anon");      //token过期提示接口
        chainDefinition.addPathDefinition(unsupportedTokenUrl,"anon");  //不支持的token类型提示接口
        // 登出功能
        chainDefinition.addPathDefinition(logoutUrl,"anon");
        // 除了以上的请求外，其它请求都需要登录
        chainDefinition.addPathDefinition("/**", "bearerHttpAuthenticationFilter");

        return chainDefinition;
    }

    /**
     * Shiro authentication filter shiro authentication filter.
     * 1，放行前后端分离的options请求
     * @return the shiro authentication filter
     */
    public BearerHttpAuthenticationFilter bearerHttpAuthenticationFilter(){

        return new ShiroAuthenticationFilter(tokenExpiredUrl,unsupportedTokenUrl);
    }

    /**
     * 自定义的 ShiroAuthenticationFilter用了@Bean在springboot项目中会注册为shiro的全局Filter
     * 将不需要注册的 Filter 注入方法即可。这时候再启动项目进行测试，就可以发现 filters 已经不存在咱们的自定义 Filter 了。
     * https://blog.csdn.net/qq_46416934/article/details/124347849
     * @param filter the filter
     * @return filter registration bean
     */
    public FilterRegistrationBean registration(BearerHttpAuthenticationFilter filter) {

        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);

        return registration;
    }

    /**
     * 定义CacheManager 实现授权缓存
     * springboot 自动帮我们注入到SessionsSecurityManager
     * @see org.apache.shiro.spring.config.AbstractShiroConfiguration#cacheManager
     * @see org.apache.shiro.spring.config.AbstractShiroConfiguration#securityManager(List)
     * @return cacheManager cache manager
     */
    public CacheManager cacheManager(){

        return new MemoryConstrainedCacheManager();
    }

    /**
     * 授权认证器
     * authorizer丢失所以我们需要自动创建一个注入到starer中
     * 丢失的原因
     * https://wenku.baidu.com/view/2243190cccc789eb172ded630b1c59eef8c79a3b.html
     * ⾃定义的Realm竟然和authorizer冲突了。Spring认为已经有authorizer的bean，⽽不再加载配置中的authorizer。
     * @see org.springframework.context.annotation.ConfigurationClassBeanDefinitionReader#loadBeanDefinitions(Set)
     * @see ShiroWebConfiguration#authorizer()
     * @return authorizer authorizer
     */
    public Authorizer authorizer() {
        ModularRealmAuthorizer authorizer = new ModularRealmAuthorizer();
        return authorizer;
    }

    /**
     * 登陆认证器
     * 为了解决多Realm 不能正常抛出异常问题特自定义实现ModularRealmAuthenticator
     * @see ShiroWebConfiguration#authenticator()
     * @return authenticator user modular realm authenticator
     */
    public Authenticator authenticator(){

        UserModularRealmAuthenticator userModularRealmAuthenticator =new UserModularRealmAuthenticator();
        userModularRealmAuthenticator.setAuthenticationStrategy(new FirstSuccessfulStrategy());

        return userModularRealmAuthenticator;
    }

 }
