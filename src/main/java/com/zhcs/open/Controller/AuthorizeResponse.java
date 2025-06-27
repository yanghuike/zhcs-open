package com.zhcs.open.Controller;

import lombok.Data;

/**
 * @author
 */
@Data
public class AuthorizeResponse {

    private String randomKey;

    private String realm;

    private String encryptType;

}
