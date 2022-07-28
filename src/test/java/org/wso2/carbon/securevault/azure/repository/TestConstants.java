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
 * Class to define the constants used.
 */
public class TestConstants {

    public static final String CONFIG_CREDENTIAL_TYPE = "credentialType";
    public static final String CONFIG_ENCRYPTION_ENABLED = "encryptionEnabled";
    public static final String CONFIG_KEY_VAULT_NAME = "keyVaultName";
    public static final String DECRYPTED_TEST_SECRET_VALUE = "decryptedValueOfSecret";
    public static final String ENCRYPTED_TEST_SECRET_NAME = "ADMIN-PASSWORD";
    public static final String ENCRYPTED_TEST_SECRET_VALUE = "encryptedValueOfSecret";
    public static final String ENCRYPTED_TEST_SECRET_VERSION = "9876";
    public static final String FIELD_BASE_CIPHER = "baseCipher";
    public static final String FIELD_ENCRYPTION_ENABLED = "encryptionEnabled";
    public static final String FIELD_LOG = "log";
    public static final String FIELD_MODIFIERS = "modifiers";
    public static final String FIELD_SECRET_CLIENT = "secretClient";
    public static final String INVALID_SECRET_NAME_CHARACTER = "#";
    public static final String RESOURCE_NOT_FOUND_EXCEPTION_MESSAGE = "Secret not found.";
    public static final String TEST_CREDENTIAL_TYPE_ENV = "env";
    public static final String TEST_KEY_VAULT_NAME = "kv-test";
    public static final String TEST_SECRET_NAME = "KEYSTORE-PASSWORD";
    public static final String TEST_SECRET_LATEST_VERSION = "5678";
    public static final String TEST_SECRET_LATEST_VERSION_VALUE = "wso2@456";
    public static final String TEST_SECRET_OLDER_VERSION = "1234";
    public static final String TEST_SECRET_OLDER_VERSION_VALUE = "wso2@123";
    public static final String UNAVAILABLE_TEST_SECRET_NAME = "KEYSSTORE-PASSWORD";
}
