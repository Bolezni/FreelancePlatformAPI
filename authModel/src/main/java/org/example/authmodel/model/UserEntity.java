package org.example.authmodel.model;


import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "_user")
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String UUID;

    private String firstName;

    private String lastName;

    private String username;

    private String email;

    private String password;
}
