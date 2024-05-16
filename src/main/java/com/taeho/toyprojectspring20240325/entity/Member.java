package com.taeho.toyprojectspring20240325.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;


// 회원 가입에 필요한 DB
@Entity
@ToString
@Getter
@Setter
// 인자 없는 생성자를 생성. 외부에서 생성을 제한하고 JPA에서만 사용하도록 설정
@NoArgsConstructor
// 모든 필드 값을 인자로 받는 생성자를 자동 생성
@AllArgsConstructor
// 빌더 패턴을 사용할 수 있게 해주는 Lombok 어노테이션
@Builder
// id 필드를 기준으로 equals와 hashCode 메서드를 자동 생성
@EqualsAndHashCode(of = "id")
public class Member implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id", updatable = false, unique = true, nullable = false)
    private Long numberid;

    @Column(unique = true)
    private String userid;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String shcoolname;

    @CreationTimestamp // 컴퓨터가 알아서 시간을 넣어준다.
    private LocalDateTime date;

    // 권한 정보를 즉시 로딩
    @ElementCollection(fetch = FetchType.EAGER)
    // 빌더 패턴 사용 시 초기 값으로 ArrayList를 할당
    @Builder.Default
    // 사용자가 가진 권한 목록
    private List<String> roles = new ArrayList<>();

    // 멤버가 가지고 있는 권한(authority) 목록을 SimpleGrantedAuthority로 변환화여 반환
    // 나머지 Override 메서드를 전부 true로 반환하도록 설정
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()
                // SimpleGrantedAuthority은 인증된 객체에 부여된 권한을 나타낸다.
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    // 계정이 만료되었는지 여부를 반환
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정이 잠겨있는지 여부를 반환
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 자격 증명(비밀번호)이 만료되었는지 여부를 반환
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정이 활성화(사용 가능) 상태인지 여부를 반환
    @Override
    public boolean isEnabled() {
        return true;
    }

}
