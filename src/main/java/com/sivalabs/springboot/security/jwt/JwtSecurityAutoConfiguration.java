package com.sivalabs.springboot.security.jwt;

import com.sivalabs.springboot.security.api.AuthenticationRestController;
import com.sivalabs.springboot.security.jwt.filter.TokenAuthenticationFilter;
import com.sivalabs.springboot.security.jwt.token.TokenHelper;
import lombok.RequiredArgsConstructor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.Arrays;

@Configuration
@ConditionalOnClass(WebSecurityConfigurerAdapter.class)
@EnableConfigurationProperties(JwtProperties.class)
public class JwtSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public TokenHelper tokenHelper(JwtProperties jwtProperties) {
        return new TokenHelper(jwtProperties);
    }

    @Configuration
    @ConditionalOnProperty(name = "security.jwt.auth-api-enabled", havingValue = "true", matchIfMissing = true)
    @ComponentScan(basePackageClasses = AuthenticationRestController.class)
    public static class DefaultAuthApiConfigurer {
    }

    @Configuration
    @EnableWebSecurity
    @EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled=true, proxyTargetClass = true)
    @RequiredArgsConstructor
    public static class ApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
        private final Log log = LogFactory.getLog(ApiWebSecurityConfigurationAdapter.class);

        private final UserDetailsService userDetailsService;
        private final TokenHelper tokenHelper;
        private final JwtProperties jwtProperties;

        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManagerBean();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            String[] permitAllPaths = jwtProperties.getPermitAllPaths().toArray(new String[0]);
            log.debug("base-path: "+ jwtProperties.getBasePath());
            log.debug("permitAllPaths: "+ Arrays.toString(permitAllPaths));
            http
                .antMatcher(jwtProperties.getBasePath())
                    .sessionManagement()
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        .and()
                    .authorizeRequests()
                        .antMatchers(permitAllPaths).permitAll()
                        .and()
                    .addFilterBefore(tokenAuthenticationFilter(), BasicAuthenticationFilter.class);
            http
                .csrf().disable();
        }

        private TokenAuthenticationFilter tokenAuthenticationFilter() {
            return new TokenAuthenticationFilter(tokenHelper, userDetailsService);
        }
    }
}
