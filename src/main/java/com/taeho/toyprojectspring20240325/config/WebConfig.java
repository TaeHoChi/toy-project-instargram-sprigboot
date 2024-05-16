package com.taeho.toyprojectspring20240325.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

// vue.js와 연결을 도와주는 CORS 설정이다.
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // 모든 매핑을 허용한다.
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:8080") // vue.js를 서비스하는 포트와 주소를 기입한다.
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE") // vue.js에서 메소드 요청을 허용할 것들을 기입한다.
                .allowedHeaders("*")  // 모든 헤더를 허용합니다.
                .allowCredentials(true);  // 쿠키를 포함한 요청을 허용합니다. 자격 증명과 함께 요청을 보낼 때 필요합니다.
    }
}