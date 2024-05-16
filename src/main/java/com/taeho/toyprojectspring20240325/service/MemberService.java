package com.taeho.toyprojectspring20240325.service;


import com.taeho.toyprojectspring20240325.dto.JoinDto;
import com.taeho.toyprojectspring20240325.dto.JoinForm;
import com.taeho.toyprojectspring20240325.dto.JwtDto;
import com.taeho.toyprojectspring20240325.dto.LoginForm;
import com.taeho.toyprojectspring20240325.jwt.JwtTokenProvider;
import com.taeho.toyprojectspring20240325.repository.MemberRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;


// JWT 토큰을 위한 서비스
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class MemberService {
    private final MemberRepository memberRepository;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public JwtDto signIn(String usernameId, String password) {

        // 1. username + password 를 기반으로 Authentication 객체 생성
        // 이때 authentication 은 인증 여부를 확인하는 authenticated 값이 false
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                usernameId, password);

        // 2. 실제 검증. authenticate() 메서드를 통해 요청된 Member 에 대한 검증 진행
        // authenticate 메서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        JwtDto jwtDto = jwtTokenProvider.generateToken(authentication);

        return jwtDto;
    }

    @Transactional
    public JoinDto signUp(JoinForm joinForm) {
        // Password 암호화
        String encodedPassword = passwordEncoder.encode(joinForm.getPassword());
        List<String> roles = new ArrayList<>();
        roles.add("USER");  // USER 권한 부여
        return JoinDto.toDto(memberRepository.save(joinForm.toEntity(encodedPassword, roles)));
    }

    // 블로그 코드
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        return  memberRepository.findByUserid(username)
//                .map(this::createUserDetails)
//                .orElseThrow(() -> new UsernameNotFoundException("해당하는 회원을 찾을 수 없습니다."));
//    }
//
//    // Spring Security에 필요한 UserDetails 객체를 생성하여 반환
//    private UserDetails createUserDetails(Member member) {
//        return User.builder()
//                .username(member.getUserid())
//                .password(passwordEncoder.encode(member.getPassword()))
//                .roles(member.getRoles().toArray(new String[0]))
//                .build();
//    }

    //토큰 유효성 검사
    @Transactional
    public ResponseEntity<?> validateTokenService(HttpServletRequest request){
        // HTTP 요청 헤더에서 Authorization을 키로 가진 값을 읽어 온다.
        String token = request.getHeader("Authorization");
        // 클라이언트에서 보낸 토큰이 존재하거나 Bearer로 시작하는 지 확인한다.
        if (token != null && token.startsWith("Bearer ")) {
            // Bearer라는 문자 이후 문자열을 실제 토큰 값으로 간주한다.
            token = token.substring(7);
            // JwtTokenProvider를 통해 토큰의 유효성을 검증한다.
            if (jwtTokenProvider.validateToken(token)) {
                // 토큰이 유효하면 200과 함께 Token is valid 메시지를 반환한다.
                return ResponseEntity.ok().body("Token is valid");
                // 토큰이 유효하지 않으면 401과 함께 Invalid or expired token을 반환한다.
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired token");
            }
        }
        // 헤더에서 토큰을 찾지 못하면 HTTP 상태 400과 No token Provided 메시지를 보낸다.
        return ResponseEntity.badRequest().body("No token provided");
    }

    // 로그아웃을 위한 기능
    @Transactional
    public ResponseEntity<?> logoutService(HttpServletResponse response) {
        // 쿠키 값에 null 값을 집어넣어 지운다.
        Cookie jwtCookie = new Cookie("jwt", null);
        // jwt 토큰을 오직 http 형태로만 받는다.
        jwtCookie.setHttpOnly(true);
        // 쿠키의 최대 유효 시간을 0으로 설정하여, 쿠키를 즉시 만료시킨다.
        jwtCookie.setMaxAge(0);
        // 쿠키의 유효 경로를 웹 사이트의 루트("/")로 설정한다.
        // 쿠키가 전체 도멘이에 대해 유효함을 의미한다.
        jwtCookie.setPath("/");
        // jwt 토큰을 응답 값으로 보낸다.
        response.addCookie(jwtCookie);
        // 토큰을 200으로 반환한다.
        return ResponseEntity.ok("Logged out successfully");
    }

    @Transactional
    public ResponseEntity<JwtDto> loginService(LoginForm loginForm){
        String usernameId = loginForm.getId();
        String password = loginForm.getPassword();
        JwtDto jwtDto = signIn(usernameId, password);
        System.out.println("jwtDto = " + jwtDto);
        log.info("request username = {}, password = {}", usernameId, password);
        log.info("jwtToken accessToken = {}, refreshToken = {}", jwtDto.getAccessToken(), jwtDto.getRefreshToken());
        return ResponseEntity.ok((jwtDto));
    }
}
