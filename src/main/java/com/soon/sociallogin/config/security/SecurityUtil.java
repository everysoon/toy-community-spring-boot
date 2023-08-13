package com.soon.sociallogin.config.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.nio.file.attribute.UserPrincipalNotFoundException;

@Component
public class SecurityUtil {
    // 어떤 user가 API 요청했는지
    public static String getCurrentUserName() throws UserPrincipalNotFoundException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication == null || authentication.getName() == null){
            throw new UserPrincipalNotFoundException("Not Found User");
        }
        return authentication.getName();
    }
    public static Authentication getAuthentication() throws UserPrincipalNotFoundException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication == null || authentication.getName() == null){
            throw new UserPrincipalNotFoundException("Not Found User");
        }
        return authentication;
    }
}