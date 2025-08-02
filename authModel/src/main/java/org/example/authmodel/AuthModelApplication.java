package org.example.authmodel;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthModelApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthModelApplication.class, args);
    }
    //      docker run --rm --name some-postgres -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=admin -e POSTGRES_DB=mydb -d -p 5432:5432 postgres
}
