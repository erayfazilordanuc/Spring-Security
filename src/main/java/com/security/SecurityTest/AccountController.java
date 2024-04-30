package com.security.SecurityTest;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;

import org.apache.catalina.connector.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity; // 
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.source.ImmutableSecret;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/account")
public class AccountController {
    
    @Value("${security.jwt.secret-key}")
    private String jwtSecretKey;

    @Value("${security.jwt.issuer}")
    private String jwtIssuer;

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private AuthenticationManager authenticationManager; // SecurityConfig sınıfında oluşturulan provider manager

    @GetMapping("/profile")
    public ResponseEntity<Object> profile(Authentication auth) {
        var response = new HashMap<String, Object>();
        response.put("Username", auth.getName());
        response.put("Authorities", auth.getAuthorities());

        var user = userRepo.findByUsername(auth.getName());
        response.put("User", user);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/secure")
    public ResponseEntity<Object> secure(Authentication auth){

        var response = new HashMap<String, Object>();

        response.put("Authorities", auth.getAuthorities());

        System.out.println(auth.getAuthorities());

        return ResponseEntity.ok("So badly secure");
    }

    @PostMapping("/register")
    public ResponseEntity<Object> register(@Valid @RequestBody RegisterDTO registerDTO, BindingResult result) {

        if(result.hasErrors()) {
            var errorList = result.getAllErrors();
            var errorsMap = new HashMap<String, String>();

            for(int i=0; i<errorList.size(); i++){
                var error  =(FieldError) errorList.get(i);
                errorsMap.put(error.getField(), error.getDefaultMessage());
            }

            return ResponseEntity.badRequest().body(errorsMap); // alınan hataları alan isimleri ile mesaj olacak şekilde mapleyerek döndürür
        }

        var bCryptEncoder = new BCryptPasswordEncoder();

        SecureUser user = new SecureUser();
        user.setFirstName(registerDTO.getFirstName());
        user.setLastName(registerDTO.getLastName());
        user.setUsername(registerDTO.getUsername());
        user.setEmail(registerDTO.getEmail());
        user.setRole("ADMIN"); // just for now
        user.setCreatedAt(new Date());
        user.setPassword(bCryptEncoder.encode(registerDTO.getPassword()));

        try {
            var otherUser = userRepo.findByUsername(registerDTO.getUsername());
            if(otherUser != null) {
                return ResponseEntity.badRequest().body("Username already used");
            }

            otherUser = userRepo.findByEmail(registerDTO.getEmail());
            if(otherUser != null) {
                return ResponseEntity.badRequest().body("Email already used");
            }
            // username ve email hiç kullanılmamışsa aşağıda kaydet
            userRepo.save(user);

            String jwtToken = createJwtToken(user);

            var response = new HashMap<String, Object>();
            response.put("token", jwtToken);
            response.put("user", user);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        return ResponseEntity.badRequest().body("Error");
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@Valid @RequestBody LoginDTO loginDTO, BindingResult result) {
        
        if(result.hasErrors()) {
            var errorList = result.getAllErrors();
            var errorsMap = new HashMap<String, String>();

            for(int i=0; i<errorList.size(); i++){
                var error  =(FieldError) errorList.get(i);
                errorsMap.put(error.getField(), error.getDefaultMessage());
            }

            return ResponseEntity.badRequest().body(errorsMap); // alınan hataları alan isimleri ile mesaj olacak şekilde mapleyerek döndürür
        }

        try {

            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword()));
        
            SecureUser user = userRepo.findByUsername(loginDTO.getUsername());

            String jwtToken = createJwtToken(user);

            var response = new HashMap<String, Object>();
            response.put("token", jwtToken);
            response.put("user", user);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.getStackTrace();
        }

        return ResponseEntity.badRequest().body("Username and password doesn't match");
    }

    private String createJwtToken(SecureUser user) { // buraya bean koymadık bak sıkıntı çıkmasın

        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtIssuer)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(24*3600))
                .subject(user.getUsername())
                .claim("role", user.getRole()) // claim'i istediğim şekilde böyle configure edebiliyoruz yani düzenleyebiliyoruz.
                .build();

        var encoder = new NimbusJwtEncoder(new ImmutableSecret<>(jwtSecretKey.getBytes()));

        var params = JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims);
        
        return encoder.encode(params).getTokenValue();
    }

}
