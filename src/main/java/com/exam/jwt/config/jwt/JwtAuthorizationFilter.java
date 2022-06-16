package com.exam.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.exam.jwt.config.auth.PrincipalDetails;
import com.exam.jwt.model.User;
import com.exam.jwt.repository.UserRepository;

// 시큐리티 필터 중 BasicAuthenticationFilter
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 필터에 걸림

public class JwtAuthorizationFilter extends BasicAuthenticationFilter{
	private UserRepository userRepository;
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}
	
	/* 인증, 권한이 필요한 주소 요청있을 때 필터링 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		System.out.println("인증이나 권한이 필요한 주소 요청");
		
		String jwtHeader = request.getHeader(JwtProperty.HEADER_STRING);
		System.out.println("JwtHeader : "+jwtHeader);
		
		/*  jwt 토큰 검증하여 정상적인 사용자인지 확인 */
		
		//header 확인
		if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
			chain.doFilter(request, response);
			return;
		}
		
		String jwtToken = request.getHeader("Authorization").replace(JwtProperty.TOKEN_PREFIX, "");
		
		String username = JWT.require(Algorithm.HMAC512(JwtProperty.SECRET)).build().verify(jwtToken).getClaim("username").asString();
		if(username != null) { // 서명이 제대로 됐으면
			User userEntity = userRepository.findByUsername(username);
			
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities()); // Jwt 토큰 서명을 통해 Authentication 객체를 만들어 강제 로그인 처리
			
			SecurityContextHolder.getContext().setAuthentication(authentication); // 세션 공간에 Authentication 객체를 저장 
		}
		chain.doFilter(request, response);
		
	}
}
