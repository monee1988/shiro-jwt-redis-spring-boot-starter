package com.github.monee1988.shiro.filter;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.github.monee1988.jwt.JwtUtils;
import org.apache.shiro.authc.BearerToken;
import org.apache.shiro.web.filter.authc.BearerHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 需要认证的url经过该过滤器
 * @author monee1988
 * @version 1.0
 * @date 2022-05-14 12:51
 */
public class ShiroAuthenticationFilter extends BearerHttpAuthenticationFilter {

    public ShiroAuthenticationFilter() {
        super();
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest servletRequest, ServletResponse servletResponse, Object mappedValue){

        //创建 bearerToken
        BearerToken bearerToken = (BearerToken) createToken(servletRequest,servletResponse);

       try {
           if(JwtUtils.isExpire(bearerToken.getToken())){
               WebUtils.redirectToSavedRequest(servletRequest, servletResponse, "/tokenExpired");
               return true;
           }
       }catch (JWTDecodeException e) {
           try {
               WebUtils.redirectToSavedRequest(servletRequest, servletResponse, "/unsupportedToken");
           } catch (IOException ex) {
               ex.printStackTrace();
           }
           return true;
       } catch (IOException e) {
           e.printStackTrace();
       }
        if(bearerToken.getToken() != null){
            try {
                return super.executeLogin(servletRequest,servletResponse);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return false;
        }
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) {
        HttpServletResponse res = (HttpServletResponse)response;
        HttpServletRequest req = (HttpServletRequest)request;
        return false;
    }

    @Override
    protected boolean preHandle(ServletRequest servletRequest, ServletResponse servletResponse) throws Exception {

        HttpServletRequest request = WebUtils.toHttp(servletRequest);
        HttpServletResponse response = WebUtils.toHttp(servletResponse);
        response.setHeader("Content-Type","application/json;charset=UTF-8");
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Access-control-Allow-Origin", request.getHeader("Origin"));
        response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
        response.setHeader("Access-Control-Allow-Headers", request.getHeader("Access-Control-Request-Headers"));

        //放行 OPTIONS 请求
        if(RequestMethod.OPTIONS.name().equalsIgnoreCase(request.getMethod())){
            return true;
        }

        return super.preHandle(servletRequest, servletResponse);
    }
}
