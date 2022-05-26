package com.github.monee1988.shiro.realm;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.github.monee1988.jwt.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Map;

/**
 * The type Jwt realm.
 *
 * @param <T> the type parameter of your User eg: SysUser
 * @author monee1988
 * @version 1.0
 * @date 2022 -05-03 10:10
 */
@Slf4j
public abstract class BearerTokenRealm<T> extends AuthorizingRealm {

    private JwtUtil jwtUtil;

    @Override
    public boolean supports(AuthenticationToken token) {
        log.info("{} supports :{}",this.getClass().getSimpleName(),token instanceof BearerToken);
        return token instanceof BearerToken;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException, TokenExpiredException {

        log.debug("BearerTokenRealm登陆认证开始,传递的token:{}", authenticationToken);

        BearerToken jwtToken = (BearerToken) authenticationToken;
        String token = jwtToken.getToken();
        if(jwtUtil.isExpire(token)){
            throw new ExpiredCredentialsException("认证已过期，请重新登陆");
        }

        //判断
        if (!jwtUtil.verifyToken(token)) {
            throw new UnknownAccountException();
        }
        Map<String, String> sysUserMap = jwtUtil.resolveJwtToken(token);
        return this.setAuthenticationInfo(sysUserMap,token);
    }

    /**
     * Sets custom user.
     *
     * @param sysUserMap the sys user map
     * @param token      the token
     * @return the custom user
     */
    protected abstract AuthenticationInfo setAuthenticationInfo(Map<String, String> sysUserMap,String token);

    @Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

        log.debug("。。。。。。BearerTokenRealm开始授权。。。。。。");

		T sysUser = (T)principalCollection.getPrimaryPrincipal();

		if (sysUser == null) {
			return null;
		}
		try {
			return setAuthorizationInfo(sysUser);
		} catch (Exception e) {
            log.debug(e.getMessage());
            throw new ShiroException("设置权限错误");
		}
	}

    /**
     * Sets simple authorization info.
     *
     * @param sysUser the sys user
     * @return the simple authorization info
     */
    protected abstract AuthorizationInfo setAuthorizationInfo(T sysUser);

    /**
     * Sets jwt util.
     *
     * @param jwtUtil the jwt util
     */
    @Autowired
    public void setJwtUtil(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }
}

