package com.taeho.toyprojectspring20240325.service;

import com.taeho.toyprojectspring20240325.config.CustomUser;
import com.taeho.toyprojectspring20240325.entity.Member;
import com.taeho.toyprojectspring20240325.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

// 사용자 인증 과정 중에 사용자 정보를 로드하는 한다.
// 데이터베이스나 다른 사용자 저장 방식과 상호작용하여 사용자 상세 정보를 검색한다.
@Service
@RequiredArgsConstructor // AutoWired 애너테이션을 입력하지 않아도 된다.
public class MyUserDetailsService implements UserDetailsService {

    // UserRepository는 JpaRepository를 확장하는 인터페이스라고 가정
    @Autowired
    private MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // DB에서 username을 가진 유저를 찾아와서
        // User(유저아이디, 비번, 권한)
        var result = memberRepository.findByUserid(username);

        if(result.isEmpty()){
            throw new UsernameNotFoundException("아이디 없음");
        }
        // Optional 타입이라 사용한다.
        var user = result.get();

        // 권한 부여
        List<GrantedAuthority> authorities = new ArrayList<>();
        // 나중에 API에서 권한을 알수 있게 메모한다.
        authorities.add(new SimpleGrantedAuthority("일반유저"));

        var a = new CustomUser(user.getUsername(), user.getPassword(), authorities);
        // 로그인 ID를 조회한다.
        a.id = user.getNumberid();
        return a;
    }

}

