/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 Inc. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 */

package org.wso2.carbon.securevault.azure.repository;

/**
 * Class to define a builder for Secrets objects.
 */
public class SecretBuilder {

    private String secretName;
    private String secretVersion;
    private String secretValue;

    public SecretBuilder secretName(String secretName) {

        this.secretName = secretName;
        return this;
    }

    public SecretBuilder secretVersion(String secretVersion) {

        this.secretVersion = secretVersion;
        return this;
    }

    public SecretBuilder secretValue(String secretValue) {

        this.secretValue = secretValue;
        return this;
    }

    public Secret build() {

        return new Secret(secretName, secretVersion, secretValue);
    }
}
