package com.github.monee1988.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The type Jwt utils.
 *
 * @author monee1988
 * @version 1.0
 * @date 2022-05-20 17:30
 */
public class JwtUtils {

    //指定一个token过期时间（毫秒）
    private long expireTime = 20 * 60 * 1000;  //20分钟

    private String tokenSecret = "monee1988";

    public JwtUtils(long expireTime,String tokenSecret) {
        this.expireTime = expireTime;
        this.tokenSecret = tokenSecret;
    }

    public void setExpireTime(long expireTime) {
        this.expireTime = expireTime;
    }

    public void setTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }

    public String createJwtTokenByUser(Map<String,String> sysUser) {

        Date date = new Date(System.currentTimeMillis() + expireTime);
        Algorithm algorithm = Algorithm.HMAC256(tokenSecret);    //使用密钥进行哈希

        JWTCreator.Builder jwt = JWT.create();

        for (Map.Entry<String, String> entry : sysUser.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            jwt = jwt.withClaim(key, value);
        }
        return jwt.withExpiresAt(date).sign(algorithm);
    }


    /**
     * 校验token是否正确
     */
    public boolean verifyTokenOfUser(String token)  {

        Algorithm algorithm = Algorithm.HMAC256(tokenSecret);

        JWTVerifier verifier = JWT.require(algorithm).build();

        verifier.verify(token);

        return true;
    }

    /**
     * 在token中获取到username信息
     */
    public String getUserKeyValue(String key,String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim(key).asString();
        } catch (JWTDecodeException e) {
            return null;
        }
    }

    public Map<String,String> recreateUserFromToken(String token, List<String> keyList) {
        Map<String,String> user = new HashMap<>();
        keyList.forEach(e->{
            user.put(e,getUserKeyValue(e,token));
        });
        return user;
    }

    /**
     * 判断是否过期
     */
    public boolean isExpire(String token) {
        DecodedJWT jwt = JWT.decode(token);
        return jwt.getExpiresAt().getTime() < System.currentTimeMillis();
    }

}


