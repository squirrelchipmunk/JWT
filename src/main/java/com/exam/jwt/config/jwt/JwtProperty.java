package com.exam.jwt.config.jwt;

public interface JwtProperty { // 실수 방지를 위해 미리 정의해두기
	String SECRET = "secretKey";
	int EXPIRATION_TIME=60000*10;
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";
}
