package com.exam.jwt.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.SequenceGenerator;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@SequenceGenerator( name= "USER_SEQ", sequenceName = "USER_SEQ", initialValue = 1, allocationSize = 1	)
@Entity(name="users")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "USER_SEQ")
	private long id;
	
	private String username;
	private String password;
	private String roles; // role이 여러 개인 사용자 -> ,로 구분
	
	public List<String> getRoleList(){
		if(this.roles.length()>0)
			return Arrays.asList(this.roles.split(","));
		else
			return new ArrayList<>();
	}
	
	
}
