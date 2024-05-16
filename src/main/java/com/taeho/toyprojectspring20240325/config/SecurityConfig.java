package com.taeho.toyprojectspring20240325.config;

import com.taeho.toyprojectspring20240325.jwt.JwtAuthenticationFiler;
import com.taeho.toyprojectspring20240325.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import org.springframework.security.web.csrf.CsrfTokenRepository;

import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;


// GPT에서 WebSecurityConfigurerAdapter 알려주지만 5.7.0-M2 부터는 지원하지 않아 변경 되었다.
// https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter
// 애플리케이션 내 보안을 처리하는 방법을 정의한다.
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;

    // 블로그 코드
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        // BCrypt Encoder 사용
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }
    //PasswordEncoder를 해야 Spring Security가 잘 동작한다.
    // new로 매번 값을 뽑는 것이 아닌 미리 뽑아서 적용한다.
    // 아무곳이나 사용할 수 있다.
    // PasswordEncoder가 유저가 제출한 비번 & DB 비번을 비교한다.
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // HttpSecurity를 구성하여 HTTP 요청에 대한 보안을 설정하는 메소드입니다.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // CSRF 보호 기능을 비활성화합니다.
        http.csrf((csrf) -> csrf.disable());
        http.httpBasic((httpBasic) -> httpBasic.disable());

        // 특정 페이지 로그인 검사할지를 결정한다.
        http.authorizeHttpRequests(
                (authorize) -> authorize
                        // **은 모든 경로 또는 /login 등으로 표현
                        // hasRole("USER)를 통해 경로에 대한 요청은 USER 권한을 가진 사용자만 가능
                        // 예시 requestMatchers("members/test").hasRole("USER")
                        .requestMatchers("/**")
                        // 모든 경로는 인증 없이 접근을 허용한다.
                        .permitAll()
                        // 이외의 모든 요청은 인증을 요구한다.
                        .anyRequest()
                        .authenticated()
        );

        // 세션을 상태 없이 관리한다.
        // JWT 토큰을 사용하기 때문에 세션을 필요하지 않다.
        // GPT에서 이렇게 알려줬다. .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        // Spring Security 6.1.0부터는 메서드 체이닝이 아니라람다식을 통해 함수령으로 설정해야 한다.
        http.sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // JWT 인증 필터를 UsernamePasswordAuthenticationFilter 이전에 추가합니다.
        return http.addFilterBefore(new JwtAuthenticationFiler(jwtTokenProvider),
                UsernamePasswordAuthenticationFilter.class).build();
    }
}


