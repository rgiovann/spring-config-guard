package dev.scg.benchmark.spring_env_benchmark;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class SpringEnvBenchmarkApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringEnvBenchmarkApplication.class, args);
	}

}
