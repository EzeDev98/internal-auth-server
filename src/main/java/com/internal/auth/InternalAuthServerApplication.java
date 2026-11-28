package com.internal.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/** Spring Boot entry point for the internal auth server. */
@SpringBootApplication
@EnableScheduling
public class InternalAuthServerApplication {
	public static void main(String[] args) {
		SpringApplication.run(InternalAuthServerApplication.class, args);
	}
}
