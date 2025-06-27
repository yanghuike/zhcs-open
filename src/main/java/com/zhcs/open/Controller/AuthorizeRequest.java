package com.zhcs.open.Controller;


import javax.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AuthorizeRequest {

    @NotBlank
    private String userName;

    private String clientType;

    @NotBlank
    private String password;

    private String randomKey;

    private String realm;

    private String signature;

    private String encryptType;
}
