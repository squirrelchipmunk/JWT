package com.exam.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import com.exam.jwt.config.jwt.JwtAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig{
	private final CorsConfig corsConfig;

	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf().disable().
		sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않는다.
		.and()
		.formLogin().disable()
		.httpBasic().disable() //  헤더의 Authorization 필드에 id, pw를 사용하지 않음 ---> token을 사용하는 방식 : Bearer
		.apply(new MyCustomDsl()) // 커스텀 필터 사용
		.and()
		.authorizeRequests((authz)-> authz
		.antMatchers("/api/v1/user/**")
			.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN') ")
		.antMatchers("/api/v1/manager/**")
			.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN') ")
		.antMatchers("/api/v1/admin/**")
			.access("hasRole('ROLE_ADMIN') ")
		.anyRequest()
			.permitAll());
		
		return http.build();
    }
	
	public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
			http
					.addFilter(corsConfig.corsFilter())  // 필터 등록
					.addFilter(new JwtAuthenticationFilter(authenticationManager));
		}
	}
}
