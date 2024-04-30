package com.security.SecurityTest;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${security.jwt.secret-key}")
    private String jwtSecretKey;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { // adreslere erişimler düzenlenir
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/").permitAll()
                        .requestMatchers("/test").permitAll()
                        .requestMatchers("/main").permitAll()
                        .requestMatchers("/account").permitAll()
                        .requestMatchers("/account/login").permitAll()
                        .requestMatchers("/account/register").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/user/**").hasRole("USER")
                        .anyRequest().authenticated()
                        )
                        .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                        .sessionManagement(session -> session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS))
                                        .build();   
    }

    @Bean
    public JwtDecoder jwtDecoder() { // verilen JWT'yi decode eder ve kullanıcının bilgilerine ulaşmamızı sağlar
        var secretKey = new SecretKeySpec(jwtSecretKey.getBytes(), "");
        return NimbusJwtDecoder.withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.HS256).build();  
    }

    @Bean
    public AuthenticationManager authenticationManager(UserService userService) { // doğrulama yapılır
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userService); // userService provider'a kullanıcı bilgilerine erişimi sağlar
        provider.setPasswordEncoder(new BCryptPasswordEncoder()); // kullanıcıların şifrelerini açık şekilde değil BCrypt algoritması ile encode edilmiş yani şifrelenmiş halde taşır. (Şifreyi şifreler)

        return new ProviderManager(provider); // ProviderManager -> Doğrulama işlemi yöneticisi
    }

}   
