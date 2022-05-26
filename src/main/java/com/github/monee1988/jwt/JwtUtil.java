package com.github.monee1988.jwt;

import java.util.Map;

/**
 * The interface Jwt util.
 *
 * @author monee1988
 * @version 1.0
 * @date 2022 -05-26 15:33
 */
public interface JwtUtil {

    /**
     * Create jwt token string.
     *
     * @param payload the payload
     * @return the string
     */
    String createJwtToken(Map<String,String> payload);

    /**
     * Verify token boolean.
     *
     * @param token the token
     * @return the boolean
     */
    boolean verifyToken(String token);

    /**
     * Resolve jwt token map.
     *
     * @param token the token
     * @return the map
     */
    Map<String,String> resolveJwtToken(String token);

    /**
     * Is expire boolean.
     *
     * @param token the token
     * @return the boolean
     */
    boolean isExpire(String token);
}
