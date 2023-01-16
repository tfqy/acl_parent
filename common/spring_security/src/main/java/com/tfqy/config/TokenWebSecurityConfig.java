package com.tfqy.config;

import com.tfqy.filter.TokenAuthenticationFilter;
import com.tfqy.filter.TokenLoginFilter;
import com.tfqy.security.DefaultPasswordEncoder;
import com.tfqy.security.TokenLogoutHandler;
import com.tfqy.security.TokenManager;
import com.tfqy.security.UnAuthEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * 2023/1/16 11:04
 *
 * @author tfqy
 */

@Configuration
public class TokenWebSecurityConfig extends WebSecurityConfigurerAdapter {

    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;
    private DefaultPasswordEncoder defaultPasswordEncoder;
    private UserDetailsService userDetailsService;

    @Autowired
    public TokenWebSecurityConfig(TokenManager tokenManager, RedisTemplate redisTemplate, DefaultPasswordEncoder defaultPasswordEncoder, UserDetailsService userDetailsService) {
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
        this.defaultPasswordEncoder = defaultPasswordEncoder;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .exceptionHandling()
                .authenticationEntryPoint(new UnAuthEntryPoint())   // 没有权限访问
                .and().csrf().disable()
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and().logout().logoutUrl("/admin/acl/index/logout")    //退出路径
                .addLogoutHandler(new TokenLogoutHandler(tokenManager, redisTemplate))
                .and().addFilter(new TokenLoginFilter(tokenManager, redisTemplate, authenticationManager()))
                .addFilter(new TokenAuthenticationFilter(authenticationManager(), tokenManager, redisTemplate))
                .httpBasic();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 调用 userDetailsService 和密码处理
        auth.userDetailsService(userDetailsService).passwordEncoder(defaultPasswordEncoder);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 不认证的路径，可以直接访问
        web.ignoring().antMatchers("/api/**");
    }
}
