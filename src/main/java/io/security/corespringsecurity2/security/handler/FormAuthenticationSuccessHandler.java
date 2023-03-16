package io.security.corespringsecurity2.security.handler;


import io.security.corespringsecurity2.domain.entity.Account;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;


@Component
public class FormAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        setDefaultTargetUrl("/");

        SavedRequest saveRequest = requestCache.getRequest(request, response);
        if(saveRequest != null) {
            String targetUrl = saveRequest.getRedirectUrl();
            redirectStrategy.sendRedirect(request, response, targetUrl);
        } else {
            redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
        }

    }

    private void addAuthCookie(HttpServletResponse response, Authentication authentication) {
        System.out.println("^^ authentication.getPrincipal() : " + authentication.getPrincipal());

        Account user = (Account) authentication.getPrincipal();

        System.out.println(user);
        String cookieValue = user.getUsername();

        if(authentication.getAuthorities() != null) {
            for (GrantedAuthority auth : authentication.getAuthorities())
                cookieValue += "," + auth.getAuthority();
        }

        try {
            String encodeCookieValue = cookieValue;

            Cookie cookie = new Cookie("auth", URLEncoder.encode(encodeCookieValue, "UTF-8"));
            cookie.setPath("/");
            response.addCookie(cookie);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        System.out.println("------------");
    }
}
