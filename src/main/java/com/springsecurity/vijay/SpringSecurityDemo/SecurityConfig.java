package com.springsecurity.vijay.SpringSecurityDemo;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    protected final Log logger = LogFactory.getLog(this.getClass());

    @Autowired
    private CustomAuthenticationManager authManager;

    public CustomUsernamePasswordAuthenticationFilter authenticationFilter() {
        CustomUsernamePasswordAuthenticationFilter filter = new CustomUsernamePasswordAuthenticationFilter();
        filter.setAuthenticationSuccessHandler(successHandler());
        filter.setAuthenticationFailureHandler(failureHandler());
        filter.setAuthenticationManager(authManager);
        return filter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(csrf -> csrf.disable())
                .addFilterAt(authenticationFilter(), UsernamePasswordAuthenticationFilter.class)
//                .authenticationManager(authManager)
                /*.httpBasic(httpBasicConfigurer ->
                        httpBasicConfigurer.authenticationEntryPoint(loginUrlAuthenticationEntryPoint()))*/
                .formLogin(formLogin -> formLogin
                        .loginProcessingUrl("/login")
                        .loginPage("/login.html")
                        .successHandler(successHandler())
                        .failureHandler(failureHandler()))
                .logout(logout -> logout.invalidateHttpSession(true).logoutUrl("/logout").logoutSuccessUrl("/login.html?Successful Logout.").deleteCookies("JSESSIONID"))
                .authorizeHttpRequests(request -> request.requestMatchers(new AntPathRequestMatcher("/login.html")).permitAll())
                .authorizeHttpRequests(request -> request.requestMatchers(new AntPathRequestMatcher("/process/**")).authenticated())
                .authorizeHttpRequests(request -> request.requestMatchers(new AntPathRequestMatcher("/role/names")).permitAll())
                .authorizeHttpRequests(request -> request.requestMatchers(new AntPathRequestMatcher("/**/**")).authenticated())
                .authorizeHttpRequests(request -> request.requestMatchers(new AntPathRequestMatcher("/login")).permitAll())
                //.httpBasic(Customizer.withDefaults())
                .build();
    }

    public SimpleUrlAuthenticationFailureHandler failureHandler() {
        SimpleUrlAuthenticationFailureHandler simpleUrlAuthenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler();
        simpleUrlAuthenticationFailureHandler.setDefaultFailureUrl("/login.html?error=true");
        return simpleUrlAuthenticationFailureHandler;
    }

    public LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint() {
        return new LoginUrlAuthenticationEntryPoint("/login.html?Please Login.");
    }

    public SavedRequestAwareAuthenticationSuccessHandler successHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setDefaultTargetUrl("/process/names");
        successHandler.setAlwaysUseDefaultTargetUrl(true);
        return successHandler;
    }
}
