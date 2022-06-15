package com.exam.jwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.exam.jwt.config.auth.PrincipalDetails;
import com.exam.jwt.dto.LoginRequestDto;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

/* 
시큐리티의 UsernamePasswordAuthenticationFilter
/loing 요청해서 username, password 전송하면 필터 동작
*/
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	private final AuthenticationManager authenticationManager;
	
	//   /login 요청을 하면 로그인 시도를 위해 실행되는 함수
	@Override
		public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
				throws AuthenticationException {
		
			System.out.println("JwtAuthenticationFilter 실행");
			
			// request의  username/password를 자바 객체로 받기
			ObjectMapper om = new ObjectMapper();
			LoginRequestDto loginRequestDto = null;
			try {
				loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
			}
			catch (Exception e) {
				e.printStackTrace();
			}
			
			System.out.println("JwtAuthenticationFilter : "+loginRequestDto);
			
			// UsernamePassword 토큰 생성
			UsernamePasswordAuthenticationToken authenticationToken = 
					new UsernamePasswordAuthenticationToken(
							loginRequestDto.getUsername(), 
							loginRequestDto.getPassword());
			
			System.out.println("JwtAuthenticationFilter : 토큰생성완료");
			
			// authenticate() 함수가 호출 되면 인증 프로바이더가 유저 디테일 서비스의
			// loadUserByUsername(토큰의 첫번째 파라메터) 를 호출하고
			// UserDetails를 리턴받아서 토큰의 두번째 파라메터(credential)과
			// UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면
			// Authentication 객체를 만들어서 필터체인으로 리턴해준다.
			
			// Tip: 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
			// Tip: 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder
			// 결론은 인증 프로바이더에게 알려줄 필요가 없음.
			Authentication authentication = 
					authenticationManager.authenticate(authenticationToken);
			
			PrincipalDetails principalDetailis = (PrincipalDetails) authentication.getPrincipal();
			System.out.println("Authentication : "+principalDetailis.getUser().getUsername());
			return authentication;
		}
	
		@Override
		protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
				Authentication authResult) throws IOException, ServletException {
			
			System.out.println("successfulAuthentication 실행"); // 인증 완료
			PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
			String jwtToken = JWT.create()
					.withSubject("토큰")
					.withExpiresAt(new Date(System.currentTimeMillis()+(60000*10)) )  // 토큰 만료 시간
					.withClaim("id", principalDetails.getUser().getId())
					.withClaim("username", principalDetails.getUser().getUsername())
					.sign(Algorithm.HMAC512("secretKey"));
			
			response.addHeader("Authorization", "Bearer "+jwtToken);
		}
}
