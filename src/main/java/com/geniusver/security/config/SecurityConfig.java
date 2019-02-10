package com.geniusver.security.config;

import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

/**
 * Created by GeniusV on 2019-02-10.
 */

@EnableWebSecurity
@Configuration
@ComponentScan
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${cas.server.url}")
    private String casUrl;

    @Value("${cas.server.login_url}")
    private String casLoginUrl;

    @Value("${cas.server.logout_url}")
    private String casLogoutUrl;

    @Value("${app.server.url}")
    private String appUrl;

    @Value("${app.login.url}")
    private String appLoginUrl;

    @Value("${app.logout.url}")
    private String appLogoutUrl;

    @Autowired
    private AuthenticationUserDetailsService<CasAssertionAuthenticationToken> userDetailsService;


    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService(appUrl + appLoginUrl);
        serviceProperties.setAuthenticateAllArtifacts(true);
        return serviceProperties;
    }

    @Bean
    public CasAuthenticationEntryPoint casAuthenticationEntryPoint() {
        CasAuthenticationEntryPoint casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
        casAuthenticationEntryPoint.setLoginUrl(casLoginUrl);
        casAuthenticationEntryPoint.setServiceProperties(serviceProperties());
        return casAuthenticationEntryPoint;
    }

    @Bean
    public Cas20ServiceTicketValidator cas20ServiceTicketValidator() {
        return new Cas20ServiceTicketValidator(casUrl);
    }

    @Bean
    public CasAuthenticationProvider casAuthenticationProvider() {
        CasAuthenticationProvider casAuthenticationProvider = new CasAuthenticationProvider();
        casAuthenticationProvider.setAuthenticationUserDetailsService(userDetailsService);
        casAuthenticationProvider.setServiceProperties(serviceProperties());
        casAuthenticationProvider.setTicketValidator(cas20ServiceTicketValidator());
        casAuthenticationProvider.setKey("testkey");
        return casAuthenticationProvider;
    }

    @Bean
    public SingleSignOutFilter singleSignOutFilter() {
        SingleSignOutFilter singleSignOutFilter = new SingleSignOutFilter();
        singleSignOutFilter.setCasServerUrlPrefix(casUrl);
        singleSignOutFilter.setIgnoreInitConfiguration(true);
        return singleSignOutFilter;
    }

    @Bean
    public LogoutFilter casLogoutFilter() {
        LogoutFilter logoutFilter = new LogoutFilter(casLogoutUrl, new SecurityContextLogoutHandler());
        logoutFilter.setFilterProcessesUrl(appLogoutUrl);
        return logoutFilter;
    }

    @Bean
    public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
        CasAuthenticationFilter casAuthenticationFilter = new CasAuthenticationFilter();
        casAuthenticationFilter.setAuthenticationManager(authenticationManager());
        casAuthenticationFilter.setFilterProcessesUrl(appLoginUrl);
        return casAuthenticationFilter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        super.configure(auth);
        auth.authenticationProvider(casAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .logout().permitAll()
                .and()
                .formLogin();
        http.exceptionHandling().authenticationEntryPoint(casAuthenticationEntryPoint())
                .and()
                .addFilter(casAuthenticationFilter())
                .addFilterBefore(casLogoutFilter(), LogoutFilter.class)
                .addFilterBefore(singleSignOutFilter(), CasAuthenticationFilter.class);
    }
}
