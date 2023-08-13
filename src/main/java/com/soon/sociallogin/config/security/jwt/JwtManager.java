package com.soon.sociallogin.config.security.jwt;

import com.soon.sociallogin.config.handler.UserServiceHandler;
import com.soon.sociallogin.config.security.SecurityUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.xml.bind.DatatypeConverter;
import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;

@RequiredArgsConstructor
@Component
public class JwtManager {
    public enum Type {
        ACCESS,
        REFESH;

        public static boolean isAccess(Type type) {
            return type == ACCESS;
        }

    }

    private String accessKey=Base64.getEncoder().encodeToString("민선이는지금너무배고파민선이는지금너무배고파민선이는지금너무배고파민선이는지금너무배고파민선이는지금너무배고파민선이는지금너무배고파".getBytes());
    private String refreshKey=Base64.getEncoder().encodeToString("시크릿키그까이꺼나중에정하지뭐점심이나정해야겠다시크릿키그까이꺼나중에정하지뭐점심이나정해야겠다시크릿키그까이꺼나중에정하지뭐점심이나정해".getBytes());

    private Duration refreshExpiration= Duration.ofDays(14);

    private Duration accessExpiration= Duration.ofMinutes(30);
    private final UserServiceHandler userDetailService;


    /**
     * 토큰 발급
     */

    public Token createTwin(Authentication authentication) {
        return Token.builder()
                .accessToken(create(authentication, Type.ACCESS))
                .refreshToken(create(authentication, Type.REFESH))
                .expiredAccess(accessExpiration)
                .expiredRefresh(refreshExpiration)
                .build();
    }

    public String create(Authentication authentication, Type tokenType) {
        Claims claims = Jwts.claims().setSubject(String.valueOf(authentication.getPrincipal()));
        claims.put("roles", authentication.getAuthorities());
        Duration expried = Type.isAccess(tokenType) ? accessExpiration : refreshExpiration;
        String secretKey = Type.isAccess(tokenType) ? accessKey : refreshKey;
        Date issuedAt = new Date();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(authentication.getName())
                .claim("scope", tokenType.name())
                .setIssuedAt(issuedAt)
                .setExpiration(new Date(issuedAt.getTime() + expried.getSeconds()))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    // JWT 토큰에서 인증 정보 조회
    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userDetailService.loadUserByUsername(getSubject(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    /**
     * 토큰에서 Claim 추출
     */
    private Claims getClaimsFormToken(String token, Type type) {
        String secretKey = Type.isAccess(type) ? accessKey : refreshKey;
        return Jwts
                .parser()
                .setSigningKey(DatatypeConverter.parseBase64Binary(secretKey))
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * 토큰에서 인증 subject 추출
     */
    private String getSubject(String token) {
        return getClaimsFormToken(token, Type.ACCESS).getSubject();
    }

    /**
     * 토큰 검증
     */
    public boolean isValidToken(String token, Type type) {
        try {
            LocalDateTime issuedAt = LocalDateTime.now();
            Claims claims = getClaimsFormToken(token, type);
            return !claims.getExpiration().before(Timestamp.valueOf(issuedAt));
        } catch (JwtException | NullPointerException exception) {
            return false;
        }
    }
}
