package com.soon.sociallogin.config.handler;

import com.soon.sociallogin.config.security.UserAdapter;
import com.soon.sociallogin.domain.User;
import com.soon.sociallogin.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceHandler implements UserDetailsService {
    private final UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.findBySocialId(username);
        if(user == null){
            throw new UsernameNotFoundException("NOT FOUND UserName");
        }
        return user.toAdapter();
    }
//    private UserDetails createUserDetails(UserAdapter user) {
//        return org.springframework.security.core.userdetails.User.builder()
//                .username(user.getUsername())
//                .password(passwordEncoder.encode(user.getPassword())) // Spring Security는 사용자 검증을 위해 encoding된 password와 그렇지 않은 password를 비교하기 때문에 인코딩 해야됌
//                .roles(user.getAuthority())
//                .build();
//    }
}
