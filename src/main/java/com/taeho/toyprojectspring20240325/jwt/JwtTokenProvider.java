package com.taeho.toyprojectspring20240325.jwt;

import com.taeho.toyprojectspring20240325.dto.JwtDto;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

// JWT 토큰을 사용하여 인증과 권한 부여를 처리한다.
// JWT 토큰의 생성, 복호화, 검증 기능을 구현
@Slf4j
@Component
public class JwtTokenProvider {
    private final Key key;

    // application.yml에서 secret 값 가져와서 key에 저장
    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        // Base64로 암호화한다.
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        // 키를 암호화한다.
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // JWT에서 userId 추출
    public String getUserIdFromToken(String token) {
        Claims claims = parseClaims(token);
        return claims.getSubject(); // "userId"는 토큰에 저장된 사용자 식별자의 클레임 이름입니다.
    }

    // Member 정보를 가지고 AccessToken, RefreshToken을 생성하는 메서드
    // generateToken()은 인증 객체를 기반으로 Access Token과 Refresh Token을 생성한다.
    // Access Token은 인증된 사용자의 권한 정보와 만료 시간을 담고 있다.
    // Refresh Token: Access Token의 갱신을 위해 사용된다.
    public JwtDto generateToken(Authentication authentication) {
        // 권한 가져오기
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        // Access Token 생성
        // 1시간의 만료 기간을 설정한다. System.currentTimeMillis() + 1000 * 60 * 60 * 10
        Date accessTokenExpiresIn = new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10);
        String accessToken = Jwts.builder()
                // 토큰에 담을 내용으로 유저 내임을 설정한다.
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                // 만료기간 설정
                .setExpiration(accessTokenExpiresIn)
                // 암호화 키를 설정
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        // Refresh Token 생성
        String refreshToken = Jwts.builder()
                .setExpiration(accessTokenExpiresIn)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return JwtDto.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
    // Jwt 토큰을 복호화하여 토큰에 들어있는 정보를 꺼내는 메서드
    // getAuthentication 주어진 Access Token을 복호화한다.
    // Claime에서 권한 정보를 추출하고 User 객체를 생성해서 Authentication 객체로 반환한다.
    public Authentication getAuthentication(String accessToken) {
        // Jwt 토큰 복호화
        Claims claims = parseClaims(accessToken);
        // Jwt 토큰이 없을 시 거절
        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        // 클레임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities = Arrays
                .stream(claims.get("auth").toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        // UserDetails 객체를 만들어서 Authentication return
        // UserDetails: interface, User: UserDetails를 구현한 class
        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    // 토큰 정보를 검증하는 메서드
    // Claims는 토큰에서 사용할 정보의 조각이다.
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    // 주어진 Access Token을 복호화하고, 만료된 토큰인 경우에도 Claimsf를 반환한다.
                    // JWT 토큰의 검증과 파싱을 모두 수행한다.
                    .parseClaimsJws(token);
            return true;
            // 상황 별 유효기간에 따라 에러를 발생시킨다.
        } catch (SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
//        } catch (ExpiredJwtException e) {
//            log.info("Expired JWT Token", e);
//        } catch (UnsupportedJwtException e) {
//            log.info("Unsupported JWT Token", e);
//        } catch (IllegalArgumentException e) {
//            log.info("JWT claims string is empty.", e);
//        }
            return false;
        }
    }


    // accessToken
    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}



