package com.exam.jwt.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.exam.jwt.model.User;
import com.exam.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

// http://localhost:8088/login 동작 x -> form 로그인을 사용하지 않아서.
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService{
	
	private final UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByUsername(username);
		return new PrincipalDetails(user);
	}

}
