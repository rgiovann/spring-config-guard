package dev.scg.benchmark.logging;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface Accounts extends JpaRepository<Account, String> {

    List<Account> findByName(String name);
}
