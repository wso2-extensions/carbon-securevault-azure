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

package org.wso2.carbon.securevault.azure.handler;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.securevault.azure.exception.AzureSecretRepositoryException;
import org.wso2.carbon.securevault.azure.repository.AzureSecretRepository;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.securevault.SecurityConstants;
import org.wso2.securevault.secret.AbstractSecretCallbackHandler;
import org.wso2.securevault.secret.SingleSecretCallback;

import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import static org.wso2.carbon.securevault.azure.commons.Constants.AZURE_SECRET_CALLBACK_HANDLER;
import static org.wso2.carbon.securevault.azure.commons.Constants.CONFIG_FILE;
import static org.wso2.carbon.securevault.azure.commons.Constants.DOT;
import static org.wso2.carbon.securevault.azure.commons.Constants.KEY;
import static org.wso2.carbon.securevault.azure.commons.Constants.STORE;

/**
 * Class defined to handle secret callbacks. This is used if the keystore and primary
 * key passwords are stored in the Azure Key Vault that stores the deployment secrets.
 */
public class AzureSecretCallbackHandler extends AbstractSecretCallbackHandler {

    private static final Log log = LogFactory.getLog(AzureSecretCallbackHandler.class);
    private static final String ALIAS = "alias";
    private static final String IDENTITY = "identity";
    private static final String SECURITY = "security";
    private static final String TRUE = "true";
    private static final String CONFIG_FILE_PATH = CarbonUtils.getCarbonConfigDirPath() +
            File.separator + SECURITY + File.separator + CONFIG_FILE;
    private static String keyStorePassword;
    private static String privateKeyPassword;

    /**
     * Handles a single secret callback.
     *
     * @param singleSecretCallback A single secret callback.
     */
    @Override
    protected void handleSingleSecretCallback(SingleSecretCallback singleSecretCallback) {

        if (StringUtils.isEmpty(keyStorePassword) || StringUtils.isEmpty(privateKeyPassword)) {
            // Flag to indicate whether the private key and keystore passwords are the same.
            boolean sameKeyAndKeyStorePass = true;
            /* If the system property "key.password" is set to "true", it indicates that the private key
            password has its own value and is not the same as the keystore password.*/
            String keyPassword = System.getProperty(KEY + DOT + SecurityConstants.PROP_PASSWORD);
            if (StringUtils.isNotEmpty(keyPassword) && TRUE.equals(keyPassword.trim())) {
                sameKeyAndKeyStorePass = false;
            }
            try {
                retrievePasswordFromKeyVault(sameKeyAndKeyStorePass);
            } catch (AzureSecretRepositoryException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Retrieval of keystore and private key password from Key Vault failed with " +
                            "exception: ", e);
                }
            }
            if (StringUtils.isEmpty(keyStorePassword) || StringUtils.isEmpty(privateKeyPassword)) {
                log.warn("Reading keystore and/or private key password from Key Vault failed.");
                readPasswordThroughConsole(sameKeyAndKeyStorePass);
            }
        }
        /*
        - If the id of the SingleSecretCallback object passed as an argument is "identity.key.password", it means the
        secret callback is for the private key password, so the private key password that was read is set as the
        secret value.
        - If the id is not "identity.key.password", it means the secret callback is for the keystore password, so the
        keystore password is set as the secret value.
        */
        if (singleSecretCallback.getId().equals(IDENTITY + DOT + KEY + DOT + SecurityConstants.PROP_PASSWORD)) {
            singleSecretCallback.setSecret(privateKeyPassword);
        } else {
            singleSecretCallback.setSecret(keyStorePassword);
        }
    }

    /**
     * Reads keystore and primary key passwords from Azure Key Vault.
     *
     * @param sameKeyAndKeyStorePass Flag to indicate whether the keystore and primary key passwords are the same.
     * @throws AzureSecretRepositoryException If reading the configuration properties from the
     *                                        secret-config.properties file fails.
     */
    @SuppressFBWarnings({"PATH_TRAVERSAL_IN"})
    private void retrievePasswordFromKeyVault(boolean sameKeyAndKeyStorePass) throws AzureSecretRepositoryException {

        if (log.isDebugEnabled()) {
            log.debug("Reading Carbon Secure Vault keystore and private key passwords from Key Vault.");
        }
        Properties properties = new Properties();
        try (InputStream inputStream = new FileInputStream(CONFIG_FILE_PATH)) {
            properties.load(inputStream);
        } catch (IOException e) {
            log.error("Error while loading configurations from " + CONFIG_FILE + " file.", e);
        }
        if (properties == null) {
            throw new AzureSecretRepositoryException("Failed to read properties from " + CONFIG_FILE + " file.");
        }
        AzureSecretRepository azureSecretRepository = new AzureSecretRepository();
        azureSecretRepository.init(properties, AZURE_SECRET_CALLBACK_HANDLER);
        String keyStoreAlias = properties.getProperty(KEY + STORE + DOT + IDENTITY + DOT + STORE + DOT + ALIAS);
        keyStorePassword = azureSecretRepository.getSecret(keyStoreAlias);
        if (sameKeyAndKeyStorePass) {
            privateKeyPassword = keyStorePassword;
        } else {
            String privateKeyAlias = properties.getProperty(KEY + STORE + DOT + IDENTITY + DOT + KEY + DOT + ALIAS);
            privateKeyPassword = azureSecretRepository.getSecret(privateKeyAlias);
        }
    }

    /**
     * Reads keystore and primary key passwords through the console if they could not be retrieved from the Key Vault.
     *
     * @param sameKeyAndKeyStorePass Flag to indicate whether the keystore and primary key passwords are the same.
     */
    private void readPasswordThroughConsole(boolean sameKeyAndKeyStorePass) {

        if (log.isDebugEnabled()) {
            log.debug("Reading Carbon Secure Vault keystore and private key passwords from console.");
        }
        Console console = System.console();
        char[] password;
        if (sameKeyAndKeyStorePass) {
            if (console != null && (password = console.readPassword("[%s]",
                    "Enter the Keystore and Private Key Password:")) != null) {
                keyStorePassword = String.valueOf(password);
                privateKeyPassword = keyStorePassword;
            }
        } else {
            if (console != null && (password = console.readPassword("[%s]",
                    "Enter the Keystore Password:")) != null) {
                keyStorePassword = String.valueOf(password);
            }
            if (console != null && (password = console.readPassword("[%s]",
                            "Enter the Private Key Password:")) != null) {
                privateKeyPassword = String.valueOf(password);
            }
        }
    }
}
