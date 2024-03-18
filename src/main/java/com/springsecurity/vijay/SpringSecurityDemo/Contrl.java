package com.springsecurity.vijay.SpringSecurityDemo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
public class Contrl {

    @GetMapping(name = "/process/names", path = "/process/names")
    //@PreAuthorize("hasRole('ROLE_USER')")
    public String getName() {
        return "Vijay";
    }

    @PostMapping(name = "/process/names", path = "/process/names")
    //@PreAuthorize("hasRole('ROLE_USER')")
    public String getNamePost() {
        return "Vijay";
    }


    @GetMapping(name = "/role/names", path = "/role/names")
    //@PreAuthorize("hasRole('ROLE_USER')")
    public String role() {
        return "Vijay_ROLE";
    }

    @GetMapping(name = "/test/service", path = "/test/service", produces = "application/json")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ModelAndView service() {
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("service.html");
        return modelAndView;
    }

    @GetMapping(name = "/books/test", path = "/books/test", produces = "application/json")
    public ModelAndView getBooks() {
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("books.html");
        return modelAndView;
    }

}
