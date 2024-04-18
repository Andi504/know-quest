package com.example.knowquest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

@SpringBootApplication
@EnableAspectJAutoProxy
public class KnowQuestApplication {

    public static void main(String[] args) {
        SpringApplication.run(KnowQuestApplication.class, args);
    }

}
