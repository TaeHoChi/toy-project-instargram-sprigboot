package com.taeho.toyprojectspring20240325.config;

import lombok.Generated;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Setter
@Getter
public class CustomUser extends User {

    public Long id;

    public CustomUser(String username,
                      String password,
                      Collection<? extends GrantedAuthority> authorities
    ) {
        // extends한 값을 그대로 가지고 온다.
        super(username, password, authorities);
    }

}
