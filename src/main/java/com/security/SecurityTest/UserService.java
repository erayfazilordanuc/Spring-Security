package com.security.SecurityTest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService{

    @Autowired
    private UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException { // kullanıcı adı ile veritabanındaki kullanıcıya erişilir ve o kullanıcının bilgilerini içeren var tipinde yeni bir UserDetail değişken oluşturulur
        
        SecureUser user = userRepo.findByUsername(username);

        if(user != null) {
            var springUser = User.withUsername(user.getUsername())
                                .password(user.getPassword())
                                .roles(user.getRole())
                                .build();

            return springUser;
        }

        return null;
    }
    
}
