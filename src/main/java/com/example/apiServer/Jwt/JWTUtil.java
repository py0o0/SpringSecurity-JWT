package com.example.apiServer.Jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

//0.12.3 방식
@Component
public class JWTUtil {

    private SecretKey secretKey;

    public JWTUtil(@Value("${jwt.secret}")String secret){
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8)
                , Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String getUsername(String token){
        return Jwts.parser().verifyWith(secretKey).build()
                .parseSignedClaims(token).getPayload().get("username", String.class);
        //키로 검증후 token에서 username 흭득
    }

    public String getCategory(String token){
        return Jwts.parser().verifyWith(secretKey).build()
                .parseSignedClaims(token).getPayload().get("category", String.class);
    }

    public String getRole(String token){
        return Jwts.parser().verifyWith(secretKey).build()
                .parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token){
        return Jwts.parser().verifyWith(secretKey).build()
                .parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String createJwt(String category,String username, String role, Long exp){
        return Jwts.builder()
                .claim("category", category)
                .claim("username",username) //페이로드
                .claim("role",role)
                .issuedAt(new Date(System.currentTimeMillis()))  //발급시간
                .expiration(new Date(System.currentTimeMillis() + exp)) //만료시간
                .signWith(secretKey).compact(); //암호화
    }
}
