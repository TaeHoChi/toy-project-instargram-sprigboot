package com.taeho.toyprojectspring20240325.jwt;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

// 클라이언트 요청 시 JWT 인증을 하기 위해 설치하는 커스텀 필터다.
// JWT를 통해 username + password 인증을 수행한다.
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFiler extends GenericFilterBean {

    private final  JwtTokenProvider jwtTokenProvider;

    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        // 1. Request Header에서 JWT 토큰 추출
        // resolveToken() 메서드를 사용하여 요청 헤더에서 JWT 토큰을 추출한다.
        String token = resolveToken((HttpServletRequest) request);

        // 2. validateToken으로 토큰 유효성 검사
        // JwtTokenProvider의 validateToken() 메서드로 JWT 토큰의 유효성 검증
        if (token != null && jwtTokenProvider.validateToken(token)) {
            // 토큰이 유효할 경우 토큰에서 Authentication 객체를 가지고 와서 SecurityContext에 저장
            // 토큰이 유효하면 JwtTokenProvider의 getAuthentication() 메서드로 인증 객체 가져와서 SecurityContext에 저장
            Authentication authentication = jwtTokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // userId 추출 및 사용
            String userId = jwtTokenProvider.getUserIdFromToken(token);
            log.info("Authenticated userId: " + userId);
        }
        // 다음 필터로 요청을 전달
        chain.doFilter(request, response);
    }

    // Request Header에서 토큰 정보 추출
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        // "Authorization" 헤더에서 "Bearer" 접두사로 시작하는 토큰을 추출하여 반환
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}