package com.github.monee1988.jwt.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.monee1988.jwt.JwtUtil;

import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The type Jwt utils.
 *
 * @author monee1988
 * @version 1.0
 * @date 2022-05-20 17:30
 */
public class JwtUtilImpl implements JwtUtil {

    private long expireTime;

    private String tokenSecret;

    public JwtUtilImpl(long expireTime, String tokenSecret) {
        this.expireTime = expireTime;
        this.tokenSecret = tokenSecret;
    }

    public void setExpireTime(long expireTime) {
        this.expireTime = expireTime;
    }

    public void setTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }

    /**
     * Genetatet jwt token string.
     * 生成token
     *
     * @param payload the payload
     * @return the string
     */
    @Override
    public String createJwtToken(Map<String,String> payload) {

        Date date = new Date(System.currentTimeMillis() + expireTime);

        JWTCreator.Builder builder = JWT.create();
        // Header
        Map<String,Object> a =  new HashMap<>(payload);
        builder.withHeader(a);
        // 构建payload
        payload.forEach((k,v) -> {
            builder.withClaim(k,v)
        ;});
        // 过期时间
        builder.withExpiresAt(date);

        return builder.sign(Algorithm.HMAC256(tokenSecret));
    }


    /**
     * Verify token boolean.
     * 校验token是否正确
     *
     * @param token the token
     * @return the boolean
     */
    @Override
    public boolean verifyToken(String token)  {

        Algorithm algorithm = Algorithm.HMAC256(tokenSecret);

        JWTVerifier verifier = JWT.require(algorithm).build();

        verifier.verify(token);

        return true;
    }


    @Override
    public Map<String,String> resolveJwtToken(String token) {
        DecodedJWT jwt = JWT.decode(token);
        Map<String, Claim> stringClaimMap =jwt.getClaims();
        Map<String, String> result = new LinkedHashMap<>();
        stringClaimMap.forEach((k,v) -> result.put(k,v.asString()));
        return result;

    }

    /**
     * 判断token是否过期
     *
     * @param token the token
     * @return the boolean
     */
    @Override
    public boolean isExpire(String token) {
        DecodedJWT jwt = JWT.decode(token);
        return jwt.getExpiresAt().getTime() < System.currentTimeMillis();
    }

}


