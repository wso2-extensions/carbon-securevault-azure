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
 * Class to represent a secret in a Key Vault.
 */
public class Secret {

    private String secretName;
    private String secretVersion;
    private String secretValue;

    public Secret(String secretName, String secretVersion, String secretValue) {
        this.secretName = secretName;
        this.secretVersion = secretVersion;
        this.secretValue = secretValue;
    }

    public String getSecretName() {
        return secretName;
    }

    public void setSecretName(String secretName) {
        this.secretName = secretName;
    }

    public String getSecretVersion() {
        return secretVersion;
    }

    public void setSecretVersion(String secretVersion) {
        this.secretVersion = secretVersion;
    }

    public String getSecretValue() {
        return secretValue;
    }

    public void setSecretValue(String secretValue) {
        this.secretValue = secretValue;
    }
}
