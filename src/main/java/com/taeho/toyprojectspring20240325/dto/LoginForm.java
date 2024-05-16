package com.taeho.toyprojectspring20240325.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@RequiredArgsConstructor
public class LoginForm {

    private String id;
    private String password;
    public String getAll(){
        return  id + password;
    }

}
