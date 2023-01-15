package com.tfqy.security;

import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * 2023/1/15 14:16
 *
 * @author tfqy
 */

@Component
public class TokenManager {

    private long tokenExpireTime = 24 * 60 * 60 * 1000;
    private String tokenSignKey = "tfqy";

    public String createToken(String username) {
        String token = Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + tokenExpireTime))
                .signWith(SignatureAlgorithm.HS512, tokenSignKey)
                .compressWith(CompressionCodecs.GZIP)
                .compact();
        return token;
    }

    public String getUserFromToken(String token) {
        String username = Jwts.parser()
                .setSigningKey(tokenSignKey)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
        return username;
    }

    public void removeToken(String token) {

    }
}
