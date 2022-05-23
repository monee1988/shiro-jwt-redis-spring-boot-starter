package com.github.monee1988.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import java.util.*;

/**
 * The type Jwt utils.
 *
 * @author monee1988
 * @version 1.0
 * @date 2022-05-20 17:30
 */
public abstract class JwtUtils {

    //指定一个token过期时间（毫秒）
    private static final long EXPIRE_TIME = 20 * 60 * 1000;  //20分钟
    private static final String JWT_TOKEN_SECRET_KEY = "yourTokenKey";
    //↑ 记得换成你自己的秘钥

    public static String createJwtTokenByUser(Map<String,String> sysUser) {

        String secret = JWT_TOKEN_SECRET_KEY;

        Date date = new Date(System.currentTimeMillis() + EXPIRE_TIME);
        Algorithm algorithm = Algorithm.HMAC256(secret);    //使用密钥进行哈希

        JWTCreator.Builder jwt = JWT.create();

        for (Map.Entry<String, String> entry : sysUser.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            jwt = jwt.withClaim(key, value);
        }

        // 附带username信息的token
        return jwt.withExpiresAt(date)  //过期时间
                .sign(algorithm);     //签名算法
        //r-p的映射在服务端运行时做，不放进token中
    }


    /**
     * 校验token是否正确
     */
    public static boolean verifyTokenOfUser(String token)  {

        String secret = JWT_TOKEN_SECRET_KEY;//
        Algorithm algorithm = Algorithm.HMAC256(secret);
        JWTVerifier verifier = JWT.require(algorithm).build();
        verifier.verify(token); // 校验不通过会抛出异常

        return true;
    }

    /**
     * 在token中获取到username信息
     */
    public static String getUserKeyValue(String key,String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim(key).asString();
        } catch (JWTDecodeException e) {
            return null;
        }
    }

    public static Map<String,String> recreateUserFromToken(String token, List<String> keyList) {
        Map<String,String> user = new HashMap<>();
        keyList.forEach(e->{
            user.put(e,getUserKeyValue(e,token));
        });
        return user;
    }

    /**
     * 判断是否过期
     */
    public static boolean isExpire(String token) {
        DecodedJWT jwt = JWT.decode(token);
        return jwt.getExpiresAt().getTime() < System.currentTimeMillis();
    }

}


