package com.github.monee1988.shiro;

import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.util.ObjectUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.Serializable;

/**
 * The type Custom session manager.
 *
 * @author monee1988
 * @version 1.0
 * @date 2022-05-14 12:51
 */
public class CustomSessionManager extends DefaultWebSessionManager {

    private static final String AUTHORIZATION_HEADER = "Authorization";

    private static final String REFERENCED_SESSION_ID_SOURCE = "Stateless request";

    public CustomSessionManager() {
        super();
//        setGlobalSessionTimeout(DEFAULT_GLOBAL_SESSION_TIMEOUT * 48);
    }

    /**
     * 前后端分离  重写SessionId的获取方式
     * @param request
     * @param response
     * @return
     */
    @Override
    protected Serializable getSessionId(ServletRequest request, ServletResponse response) {
        // 只有设置 AUTHORIZATION 才能正确识别用户信息
        String sessionId = WebUtils.toHttp(request).getHeader(AUTHORIZATION_HEADER);
        if (!ObjectUtils.isEmpty(sessionId)) {
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE, REFERENCED_SESSION_ID_SOURCE);
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, sessionId);
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
            return sessionId;
        } else {
            return super.getSessionId(request, response);
        }
    }


}
