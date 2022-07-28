/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.securevault.azure.repository;

import com.azure.core.exception.ResourceNotFoundException;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import org.apache.commons.logging.Log;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.internal.util.reflection.FieldSetter;
import org.wso2.securevault.DecryptionProvider;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.securevault.azure.commons.Constants.VERSION_DELIMITER;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.DECRYPTED_TEST_SECRET_VALUE;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.ENCRYPTED_TEST_SECRET_NAME;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.ENCRYPTED_TEST_SECRET_VALUE;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.FIELD_BASE_CIPHER;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.FIELD_ENCRYPTION_ENABLED;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.FIELD_SECRET_CLIENT;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.INVALID_SECRET_NAME_CHARACTER;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.RESOURCE_NOT_FOUND_EXCEPTION_MESSAGE;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.TEST_SECRET_LATEST_VERSION_VALUE;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.TEST_SECRET_NAME;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.TEST_SECRET_OLDER_VERSION;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.TEST_SECRET_OLDER_VERSION_VALUE;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.UNAVAILABLE_TEST_SECRET_NAME;

/**
 * Test class for AzureSecretRepository.
 */
public class AzureSecretRepositoryTest {

    private static AzureSecretRepository azureSecretRepository = new AzureSecretRepository();
    private static Secret encryptedTestSecret;
    private static Secret olderVersionOfTestSecret;
    private static Secret latestVersionOfTestSecret;

    @Mock
    private static SecretClient secretClient = mock(SecretClient.class);

    @Mock
    private static DecryptionProvider baseCipher = mock(DecryptionProvider.class);

    @Mock
    private static Log log = mock(Log.class);

    @BeforeAll
    public static void setUp() throws NoSuchFieldException, IllegalAccessException {

        // Prevent logging to keep console clean:
        Mockito.doNothing().when(log).info(anyString());
        Mockito.doNothing().when(log).error(anyString());
        Mockito.doNothing().when(log).error(anyString(), any(Throwable.class));
        when(log.isDebugEnabled()).thenReturn(false);
        Field field = AzureSecretRepository.class.getDeclaredField("log");
        field.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        FieldSetter.setField(azureSecretRepository, field, log);

        FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                FIELD_SECRET_CLIENT), secretClient);
        olderVersionOfTestSecret = SecretDataFactory.createOlderVersionOfSecret();
        latestVersionOfTestSecret = SecretDataFactory.createLatestVersionOfSecret();
        encryptedTestSecret = SecretDataFactory.createEncryptedSecret();
        mockSecretClientRetrieval(olderVersionOfTestSecret.getSecretName(), olderVersionOfTestSecret.getSecretVersion(),
                olderVersionOfTestSecret.getSecretValue());
        mockSecretClientRetrieval(latestVersionOfTestSecret.getSecretName(),
                latestVersionOfTestSecret.getSecretVersion(), latestVersionOfTestSecret.getSecretValue());
        mockSecretClientRetrieval(latestVersionOfTestSecret.getSecretName(), "",
                latestVersionOfTestSecret.getSecretValue());
        mockSecretClientRetrieval(latestVersionOfTestSecret.getSecretName(), null,
                latestVersionOfTestSecret.getSecretValue());
        mockSecretClientRetrieval(encryptedTestSecret.getSecretName(), null,
                encryptedTestSecret.getSecretValue());
        when(baseCipher.decrypt(ENCRYPTED_TEST_SECRET_VALUE.getBytes(StandardCharsets.UTF_8))).thenReturn(
                DECRYPTED_TEST_SECRET_VALUE.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void testSecretRetrievalUsingSecretNameOnly() {

        String actualSecretValue = azureSecretRepository.getSecret(TEST_SECRET_NAME);
        assertEquals(TEST_SECRET_LATEST_VERSION_VALUE, actualSecretValue);
    }

    @Test
    public void testSecretRetrievalUsingSecretNameAndVersion() {

        String actualSecretValue = azureSecretRepository.getSecret(TEST_SECRET_NAME + VERSION_DELIMITER +
                TEST_SECRET_OLDER_VERSION);
        assertEquals(TEST_SECRET_OLDER_VERSION_VALUE, actualSecretValue);
    }

    @Test
    public void testRetrievalOfSecretNotInKeyVault() {

        when(secretClient.getSecret(UNAVAILABLE_TEST_SECRET_NAME, null)).thenThrow(new
                ResourceNotFoundException(RESOURCE_NOT_FOUND_EXCEPTION_MESSAGE, null));
        String actualSecretValue = azureSecretRepository.getSecret(UNAVAILABLE_TEST_SECRET_NAME);
        String expectedSecretValue = "";
        assertEquals(expectedSecretValue, actualSecretValue);
    }

    @Test
    public void testSecretReferenceWithVersionDelimiterButNoVersion() {

        String actualSecretValue = azureSecretRepository.getSecret(TEST_SECRET_NAME + VERSION_DELIMITER);
        assertEquals(TEST_SECRET_LATEST_VERSION_VALUE, actualSecretValue);
    }

    @Test
    public void testSecretRetrievalUsingSecretNameWithInvalidRegex() {

        String actualSecretValue = azureSecretRepository.getSecret(TEST_SECRET_NAME + INVALID_SECRET_NAME_CHARACTER);
        String expectedSecretValue = "";
        assertEquals(expectedSecretValue, actualSecretValue);
    }

    @Test
    public void testSecretRetrievalUsingEmptySecretReference() {

        String actualSecretValue = azureSecretRepository.getSecret("");
        String expectedSecretValue = "";
        assertEquals(expectedSecretValue, actualSecretValue);
    }

    @Test
    public void testSecretReferenceUsingSecretVersionOnly() {

        String actualSecretValue = azureSecretRepository.getSecret(VERSION_DELIMITER + TEST_SECRET_OLDER_VERSION);
        String expectedSecretValue = "";
        assertEquals(expectedSecretValue, actualSecretValue);
    }

    @Test
    public void testSecretRetrievalUsingSecretReferenceComprisingVersionDelimiterOnly() {

        String actualSecretValue = azureSecretRepository.getSecret(VERSION_DELIMITER);
        String expectedSecretValue = "";
        assertEquals(expectedSecretValue, actualSecretValue);
    }

    @Test
    public void testEncryptedSecretRetrievalWhileEncryptionEnabled() {

        try {
            FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                    FIELD_ENCRYPTION_ENABLED), true);
            FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                    FIELD_BASE_CIPHER), baseCipher);
            String actualSecretValue = azureSecretRepository.getSecret(ENCRYPTED_TEST_SECRET_NAME);
            String expectedSecretValue = DECRYPTED_TEST_SECRET_VALUE;
            assertEquals(expectedSecretValue, actualSecretValue);
        } catch (NoSuchFieldException e) {
            // do nothing
        } finally {
            try {
                FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                        FIELD_ENCRYPTION_ENABLED), false);
                FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                        FIELD_BASE_CIPHER), null);
            } catch (NoSuchFieldException e) {
                // do nothing
            }
        }
    }

    @Test
    public void trySecretRetrievalWhileNullSecretClient() {

        try {
            FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                    FIELD_SECRET_CLIENT), null);
            String actualSecretValue = azureSecretRepository.getSecret(TEST_SECRET_NAME);
            String expectedSecretValue = "";
            assertEquals(expectedSecretValue, actualSecretValue);
        } catch (NoSuchFieldException e) {
            // do nothing
        } finally {
            try {
                FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                        FIELD_SECRET_CLIENT), secretClient);
            } catch (NoSuchFieldException e) {
                // do nothing
            }
        }
    }

    @Test
    public void testEncryptedDataRetrievalWhileEncryptionEnabled() {

        try {
            FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                    FIELD_ENCRYPTION_ENABLED), true);
            String actualSecretValue = azureSecretRepository.getEncryptedData(ENCRYPTED_TEST_SECRET_NAME);
            String expectedSecretValue = ENCRYPTED_TEST_SECRET_VALUE;
            assertEquals(expectedSecretValue, actualSecretValue);
        } catch (NoSuchFieldException e) {
            // do nothing
        } finally {
            try {
                FieldSetter.setField(azureSecretRepository, azureSecretRepository.getClass().getDeclaredField(
                        FIELD_ENCRYPTION_ENABLED), false);
            } catch (NoSuchFieldException e) {
                // do nothing
            }
        }
    }

    @Test
    public void testEncryptedSecretRetrievalWhileEncryptionDisabled() {

        assertThrows(UnsupportedOperationException.class, () -> azureSecretRepository.getEncryptedData(
                ENCRYPTED_TEST_SECRET_NAME));
    }

    private static void mockSecretClientRetrieval(String secretName, String secretVersion, String secretValue) {

        KeyVaultSecret keyVaultSecret1 = mock(KeyVaultSecret.class);
        when(secretClient.getSecret(secretName, secretVersion)).thenReturn(keyVaultSecret1);
        when(keyVaultSecret1.getValue()).thenReturn(secretValue);
    }
}
