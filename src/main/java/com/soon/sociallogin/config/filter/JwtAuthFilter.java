package com.soon.sociallogin.config.filter;

import com.soon.sociallogin.config.security.jwt.JwtManager;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthFilter extends GenericFilterBean {
    private final JwtManager jwtManager;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String token = resolveToken((HttpServletRequest) request);
        if (jwtManager.isValidToken(token, JwtManager.Type.ACCESS) && token != null) {
            /**
             * security가 만들어주는 securityContextHolder 그 안에 authentication을 넣어줍니다.
             * security가 securitycontextholder에서 인증 객체를 확인하는데
             * jwtAuthfilter에서 authentication을 넣어주면 UsernamePasswordAuthenticationFilter 내부에서
             * 인증이 된 것을 확인하고 추가적인 작업을 진행하지 않습니다.
             */
            SecurityContextHolder.getContext().setAuthentication(jwtManager.getAuthentication(token));
        }

        chain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
            return bearerToken.substring(7);
        }
        return null;
    }


}
