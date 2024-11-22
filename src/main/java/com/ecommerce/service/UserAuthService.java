package com.ecommerce.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.ecommerce.models.User;
import com.ecommerce.repository.UserRepository;

@Service
public class UserAuthService implements UserDetailsService {
	@Autowired
	UserRepository userRepository;

	public User loadUserByUserID(Integer id) {
		Optional<User> user = userRepository.findById(id);
		if (user.isPresent()) {
			return user.get();
		} else
			throw new UsernameNotFoundException("User ID not found");
	}

	@Override
	public User loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<User> user = userRepository.findByUsername(username);
		if (user.isPresent()) {
			return user.get();
		} else
			throw new UsernameNotFoundException("User ID not found");
	}
}
