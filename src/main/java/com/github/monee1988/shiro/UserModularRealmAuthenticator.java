package com.github.monee1988.shiro;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.realm.Realm;

import java.util.ArrayList;
import java.util.Collection;

/**
 * The type User modular realm authenticator.
 *
 * @author monee1988
 * @version 1.0
 * @date 2022-05-19 15:05
 */
@Slf4j
public class UserModularRealmAuthenticator extends ModularRealmAuthenticator {

    @Override
    protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {

        // 判断getRealms()是否返回为空
        assertRealmsConfigured();
        // 所有Realm
        Collection<Realm> realms = getRealms();
        // 登录类型对应的所有Realm
        Collection<Realm> typeRealms = new ArrayList<>();
        for (Realm realm : realms) {
            if (realm.supports(authenticationToken)){
                typeRealms.add(realm);
            }
        }

        if (typeRealms.size() == 1) {
            log.debug("UserModularRealmAuthenticator use one relam");
            return doSingleRealmAuthentication(typeRealms.iterator().next(), authenticationToken);
        }
        log.debug("UserModularRealmAuthenticator use {} relams",typeRealms.size());
        return doMultiRealmAuthentication(typeRealms, authenticationToken);
    }
}
