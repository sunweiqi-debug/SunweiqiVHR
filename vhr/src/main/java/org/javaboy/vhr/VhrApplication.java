package org.javaboy.vhr;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@MapperScan(basePackages = "org.javaboy.vhr.mapper")
@SpringBootApplication
public class VhrApplication {
    public static void main(String[] args) {
        SpringApplication.run(VhrApplication.class, args);
    }

}
