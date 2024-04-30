package com.security.SecurityTest;

import org.springframework.web.bind.annotation.*;

@RestController
// @RequestMapping("/security")
public class MainController {

    @GetMapping("/") // change it to /home
    public String welcome(){
        return "Welcome to home page!";
    }

    @GetMapping("/main")
    public String main(){
        return "Welcome to the main!";
    }

    @GetMapping("/admin/home")
    public String admin(){
        return "Welcome to admin page!";
    }

    @GetMapping("/client/home")
    public String client(){
        return "Welcome to client page!";
    }

    @GetMapping("/test")
    public String test(){
        return "Welcome to the test!";
    }

}