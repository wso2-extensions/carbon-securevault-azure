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

package org.wso2.carbon.securevault.azure.commons;

import org.apache.commons.logging.Log;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.internal.util.reflection.FieldSetter;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.securevault.azure.commons.Constants.NOVEL_CONFIG_PREFIX;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.CONFIG_CREDENTIAL_TYPE;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.CONFIG_ENCRYPTION_ENABLED;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.CONFIG_KEY_VAULT_NAME;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.FIELD_LOG;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.FIELD_MODIFIERS;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.TEST_CREDENTIAL_TYPE_ENV;
import static org.wso2.carbon.securevault.azure.repository.TestConstants.TEST_KEY_VAULT_NAME;

/**
 * Test class for ConfigUtils.
 */
public class ConfigUtilsTest {

    private static ConfigUtils configUtils = ConfigUtils.getInstance();
    private static Properties properties = new Properties();

    @Mock
    private static Log log = mock(Log.class);

    @BeforeAll
    public static void setUp() throws NoSuchFieldException, IllegalAccessException {

        // Prevents logging to keep console clean.
        Mockito.doNothing().when(log).info(anyString());
        Mockito.doNothing().when(log).error(anyString());
        Mockito.doNothing().when(log).error(anyString(), any(Throwable.class));
        when(log.isDebugEnabled()).thenReturn(false);
        Field field = ConfigUtils.class.getDeclaredField(FIELD_LOG);
        field.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField(FIELD_MODIFIERS);
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        FieldSetter.setField(configUtils, field, log);

        properties.put(NOVEL_CONFIG_PREFIX + CONFIG_CREDENTIAL_TYPE, TEST_CREDENTIAL_TYPE_ENV);
    }

    @Test
    public void testConfigRetrievalFromFile() {

        String actualConfigValue = configUtils.getAzureSecretRepositoryConfig(properties, CONFIG_CREDENTIAL_TYPE);
        assertEquals(TEST_CREDENTIAL_TYPE_ENV, actualConfigValue);
    }

    @Test
    public void testConfigRetrievalFromEnv() {

        String actualConfigValue = configUtils.getAzureSecretRepositoryConfig(properties, CONFIG_KEY_VAULT_NAME);
        assertEquals(TEST_KEY_VAULT_NAME, actualConfigValue);
    }

    @Test
    public void testUnavailableConfigRetrieval() {

        String actualConfigValue = configUtils.getAzureSecretRepositoryConfig(properties, CONFIG_ENCRYPTION_ENABLED);
        assertNull(actualConfigValue);
    }
}
