package com.example.oauth2_device_code_test;

import com.example.oauth2_device_code_test.controller.AuthorizationConsentController;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.thymeleaf.expression.Lists;

import java.util.Arrays;

@SpringBootApplication
@ImportRuntimeHints(Oauth2DeviceCodeTestApplication.DemoAuthorizationServerApplicationRuntimeHintsRegistrar.class)
public class Oauth2DeviceCodeTestApplication {

    static class DemoAuthorizationServerApplicationRuntimeHintsRegistrar implements RuntimeHintsRegistrar {

        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            // Thymeleaf
            hints.reflection().registerTypes(
                    Arrays.asList(
                            TypeReference.of(AuthorizationConsentController.ScopeWithDescription.class),
                            TypeReference.of(Lists.class)
                    ), builder ->
                            builder.withMembers(MemberCategory.DECLARED_FIELDS,
                                    MemberCategory.INVOKE_DECLARED_CONSTRUCTORS, MemberCategory.INVOKE_DECLARED_METHODS)
            );
        }

    }

    public static void main(String[] args) {
        SpringApplication.run(Oauth2DeviceCodeTestApplication.class, args);
    }
}
