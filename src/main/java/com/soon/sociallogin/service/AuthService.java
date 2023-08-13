package com.soon.sociallogin.service;

import com.soon.sociallogin.config.security.jwt.JwtManager;
import com.soon.sociallogin.config.security.jwt.Token;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final ClientRegistrationRepository clientRegistrationRepository;

    private String generateState() {
        SecureRandom random = new SecureRandom();
        return new BigInteger(130, random).toString(32);
    }

    public void login(

            Authentication authentication,
            HttpServletResponse response
    ) throws IOException {

        String authorizationUri = UriComponentsBuilder.fromUriString("http://localhost:7022/auth")
                .queryParam("access_token", "111")
                .queryParam("refresh_token", "222")
                .queryParam("provider","kakao")
                .build().encode(StandardCharsets.UTF_8).toUriString();
        response.sendRedirect(authorizationUri);
    }

}
