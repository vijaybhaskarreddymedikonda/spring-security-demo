package com.springsecurity.vijay.SpringSecurityDemo;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.List;

/**
 * A custom authentication manager that allows access if the user details
 * exist in the database and if the username and password are not the same.
 * Otherwise, throw a {@link BadCredentialsException}
 */
@Configuration
public class CustomAuthenticationManager implements AuthenticationManager {

    private final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final String name = authentication.getName();
        final String password = authentication.getCredentials().toString();
        System.out.println("Username " + name + " password " + password + " in CustomAuthManager");
        if (!"superuser".equals(name) || !"superpassword".equals(password)) {
            throw new BadCredentialsException("Unable to validate the userid/password combination!");
        }
        UsernamePasswordAuthenticationToken username = authenticateAgainstThirdPartyAndGetAuthentication(name, password);
        System.out.println("Vijay is Authenticated " + username.isAuthenticated());
        return username;
    }

    private UsernamePasswordAuthenticationToken authenticateAgainstThirdPartyAndGetAuthentication(String name, String password) {
        final List<GrantedAuthority> grantedAuths = new ArrayList<>();
        grantedAuths.add(new SimpleGrantedAuthority("ROLE_LC_ADMIN"));
        grantedAuths.add(new SimpleGrantedAuthority("ROLE_LC_SERVICE_LIGHTING_CONTROL"));
        final UserDetails principal = new org.springframework.security.core.userdetails.User(name, password, grantedAuths);
        return new UsernamePasswordAuthenticationToken(principal, password, grantedAuths);
    }


}