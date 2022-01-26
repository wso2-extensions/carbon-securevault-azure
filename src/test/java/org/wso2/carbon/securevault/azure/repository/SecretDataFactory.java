/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 Inc. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 */

package org.wso2.carbon.securevault.azure.repository;

import static org.wso2.carbon.securevault.azure.repository.TestConstants.ENCRYPTED_TEST_SECRET_NAME;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.ENCRYPTED_TEST_SECRET_VALUE;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.ENCRYPTED_TEST_SECRET_VERSION;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.TEST_SECRET_LATEST_VERSION;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.TEST_SECRET_LATEST_VERSION_VALUE;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.TEST_SECRET_NAME;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.TEST_SECRET_OLDER_VERSION;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.TEST_SECRET_OLDER_VERSION_VALUE;

/**
 * Class to build secrets with valid data.
 */
public class SecretDataFactory {

    private SecretDataFactory() {}

    public static Secret createOlderVersionOfSecret() {

        return new SecretBuilder()
                .secretName(TEST_SECRET_NAME)
                .secretVersion(TEST_SECRET_OLDER_VERSION)
                .secretValue(TEST_SECRET_OLDER_VERSION_VALUE)
                .build();
    }

    public static Secret createLatestVersionOfSecret() {

        return new SecretBuilder()
                .secretName(TEST_SECRET_NAME)
                .secretVersion(TEST_SECRET_LATEST_VERSION)
                .secretValue(TEST_SECRET_LATEST_VERSION_VALUE)
                .build();
    }

    public static Secret createEncryptedSecret() {

        return new SecretBuilder()
                .secretName(ENCRYPTED_TEST_SECRET_NAME)
                .secretVersion(ENCRYPTED_TEST_SECRET_VERSION)
                .secretValue(ENCRYPTED_TEST_SECRET_VALUE)
                .build();
    }
}
