package com.exam.jwt.filter;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter1 implements Filter{

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		// 로그인 완료되면 토큰을 만들어주고 응답
		// 요청할 때마다 header Authorization value 값에 토큰 값
		// 토큰이 내가 만든 토큰이 맞는지 검증.
		
		if(req.getMethod().equals("POST")) {
			System.out.println("post 요청");
			String headerAuth = req.getHeader("Authorization");
			System.out.println(headerAuth);
			System.out.println("필터 1");
			
			if(headerAuth.equals("token")) {
				chain.doFilter(request, response);
			}else {
				res.getOutputStream().write("인증안됨".getBytes());;
			}
		}

		chain.doFilter(request, response);
	}
	
}
