package com.exam.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

import com.exam.jwt.filter.MyFilter3;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig{

	private final CorsFilter corsFilter;
	
	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.addFilterBefore(new MyFilter3(), UsernamePasswordAuthenticationFilter.class);
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않는다.
		.and()
		.addFilter(corsFilter) // @CrossOrigin (인증 x), 필터에 등록 (인증 O)
		.formLogin().disable()
		.httpBasic().disable() //  헤더의 Authorization 필드에 id, pw를 사용하지 않음 ---> token을 사용하는 방식 : Bearer
		.authorizeRequests()
		.antMatchers("/api/v1/user/**")
			.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN') ")
		.antMatchers("/api/v1/manager/**")
			.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN') ")
		.antMatchers("/api/v1/admin/**")
			.access("hasRole('ROLE_ADMIN') ")
		.anyRequest()
			.permitAll();
		
		return http.build();
    }
}