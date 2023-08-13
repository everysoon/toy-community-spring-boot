package com.soon.sociallogin.config.oauth2;

import com.soon.sociallogin.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.security.Provider;
import java.util.Map;

@Service
public class OAuth2UserService extends DefaultOAuth2UserService {
    private UserRepository userRepository;
    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) {
        System.out.println(oAuth2UserRequest);
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);
        System.out.println(oAuth2User);
        Map<String,Object> userInfoAttributes = oAuth2User.getAttributes();
//        if (!userInfoAttributes.containsKey("email")) {
//            throw new IllegalArgumentException("서드파티의 응답에 email이 존재하지 않습니다!!!");
//        }
        System.out.println(userInfoAttributes);
        String provider = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        signInUser(userInfoAttributes,provider);
        return oAuth2User;
    }
    private void signInUser(Map<String,Object> userInfoAttributes, String provider){

    }
}
