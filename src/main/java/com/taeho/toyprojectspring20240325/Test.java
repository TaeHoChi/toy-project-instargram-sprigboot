package com.taeho.toyprojectspring20240325;

import com.taeho.toyprojectspring20240325.dto.LoginForm;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
@Slf4j
public class Test {

    private final Key key;

    // application.yml에서 secret 값 가져와서 key에 저장
    public Test(@Value("${jwt.secret}") String secretKey) {
        // Base64로 암호화한다.
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        // 키를 암호화한다.
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // id와 passwd를 받아온다.
    // RequestBody는 하나의 에너테이션만 사용이 가능해서 따로 클래스를 만들어 사용한다.
    @Getter
    @Setter
    static public class Login {
        private String id;
        private String passwd;
    }


    @PostMapping("/test")
    public Authentication getAuthentication(@RequestBody String accessToken) {
        Claims claims = parseClaims(accessToken);
        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        // 사용자 ID 추출
        String userId = claims.getSubject(); // 사용자 ID는 subject 클레임에 저장됩니다.

        Collection<? extends GrantedAuthority> authorities = Arrays
                .stream(claims.get("auth").toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        UserDetails principal = new User(userId, "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

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
