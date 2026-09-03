package com.internal.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Collections;

@Configuration
public class SwaggerCustomConfig {

    @Value("${base-url}")
    private String baseUrl;

    @Bean
    public OpenAPI openAPI() {

        OpenAPI openAPI = new OpenAPI();
        openAPI.setOpenapi("3.0.1");
        return openAPI
                .info(new Info()
                        .title("Internal Auth App")
                        .description("Internal Auth APIs")
                        .version("1.0")
                        .contact(new Contact()
                                .name("BWE")
                                .email("buildingwitheze@gmail.com")
                                .url("https://www.buildingwitheze.com"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0")))
                .servers(Collections.singletonList(
                        new Server()
                                .url(baseUrl)
                                .description("API Server")))
                .components(new Components()
                        .addSecuritySchemes("Bearer Authentication", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("Enter JWT Bearer token")))
                .addSecurityItem(new SecurityRequirement()
                        .addList("Bearer Authentication"));
    }
}