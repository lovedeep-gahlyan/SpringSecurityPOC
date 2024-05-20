package com.security.demo.service;

import com.security.demo.dto.AuthenticationRequest;
import com.security.demo.dto.AuthenticationResponse;
import com.security.demo.dto.RegisterRequest;
import com.security.demo.model.User;
import com.security.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;

    private final JwtService jwtService;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;


    public AuthenticationResponse register(RegisterRequest registerRequest){
        var user = User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(registerRequest.getRole())
                .build();
        var savedUser = userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().accessToken(jwtToken).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
            //FirstStep
            //We need to validate our request (validate whether password & username is correct)
            //Verify whether user present in the database
            //Which AuthenticationProvider -> DaoAuthenticationProvider (Inject)
            //We need to authenticate using authenticationManager injecting this authenticationProvider
            //SecondStep
            //Verify whether userName and password is correct => UserNamePasswordAuthenticationToken
            //Verify whether user present in db
            //generateToken
            //Return the token
            authenticationManager.authenticate(
                    // authentication object as talked after the filter
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
            var user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow();
            String jwtToken = jwtService.generateToken(user);
            return AuthenticationResponse.builder().accessToken(jwtToken).build();

        }
}

