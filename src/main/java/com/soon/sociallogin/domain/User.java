package com.soon.sociallogin.domain;

import com.soon.sociallogin.config.security.UserAdapter;
import io.jsonwebtoken.io.Encoders;
import lombok.Getter;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String socialId;
    private String username; // security

    private String email;
    private String profileImg;
    private String name;
    private String nickName;
    private String gender;
    private String age;
    private String birth;
    private Role role;
    public String getUserName() {
        return Encoders.BASE64.encode(socialId.getBytes());
    }

    public UserAdapter toAdapter(){
        return UserAdapter.builder()
                .username(getUserName())
                .password(socialId)
                .authorities(List.of(role.name()))
                .build();
    }

}
