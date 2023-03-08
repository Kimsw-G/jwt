package com.security.las;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

@SpringBootTest
class JwtApplicationTests {

	@Autowired
	private ApplicationContext applicationContext;

	@Test
	public void contextLoads() throws Exception {
		System.out.println("hi");
		if (applicationContext != null) {
			String[] beans = applicationContext.getBeanDefinitionNames();

			for (String bean : beans) {
				System.out.println("bean : " + bean);
			}
		}
	}

}
