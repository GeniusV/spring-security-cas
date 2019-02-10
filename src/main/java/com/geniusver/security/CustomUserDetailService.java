package com.geniusver.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by GeniusV on 2019-02-10.
 */
@Service
public class CustomUserDetailService implements UserDetailsService, AuthenticationUserDetailsService<CasAssertionAuthenticationToken> {
    private Logger logger = LoggerFactory.getLogger(CustomUserDetailService.class);

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        logger.info("Loading UserDetail: {}", s);
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("test"));
        User user = new User(s, "123456", authorities);
        return user;
    }

    @Override
    public UserDetails loadUserDetails(CasAssertionAuthenticationToken token) throws UsernameNotFoundException {
        String username = token.getName();
        logger.info("Loading UserDetail by cas token: {}", username);
        return loadUserByUsername(username);
    }
}
