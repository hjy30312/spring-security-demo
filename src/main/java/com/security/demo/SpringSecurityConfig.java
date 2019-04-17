package com.security.demo;


import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /**
         * 在inMemoryAuthentication()后面多了".passwordEncoder(new BCryptPasswordEncoder())",
         * 这相当于登陆时用BCrypt加密方式对用户密码进行处理。
         * 以前的".password("123456")" 变成了 ".password(new BCryptPasswordEncoder().encode("123456"))" ，
         * 这相当于对内存中的密码进行Bcrypt编码加密。比对时一致，说明密码正确，允许登陆。
         * ---------------------
         * 作者：Canon_in_D_Major
         * 来源：CSDN
         * 原文：https://blog.csdn.net/canon_in_d_major/article/details/79675033
         * 版权声明：本文为博主原创文章，转载请附上博文链接！
         */
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("test").password(new BCryptPasswordEncoder().encode("test")).roles("ADMIN");
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("test1").password(new BCryptPasswordEncoder().encode("test1")).roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .anyRequest().authenticated()
                .and()
                .logout().permitAll()
                .and()
                .formLogin();
        http.csrf().disable();

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
         web.ignoring().antMatchers("/js/**", "/css/**", "images/**");
    }

}
