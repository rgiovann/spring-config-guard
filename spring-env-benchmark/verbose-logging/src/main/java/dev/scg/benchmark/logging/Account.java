package dev.scg.benchmark.logging;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity
public class Account {

    @Id
    String name;
}
