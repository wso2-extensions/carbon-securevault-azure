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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.securevault.azure.commons.ConfigUtils;
import org.wso2.carbon.securevault.azure.exception.AzureSecretRepositoryException;
import org.wso2.securevault.CipherFactory;
import org.wso2.securevault.CipherOperationMode;
import org.wso2.securevault.DecryptionProvider;
import org.wso2.securevault.EncodingType;
import org.wso2.securevault.definition.CipherInformation;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.KeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;

import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.wso2.carbon.securevault.azure.commons.Constants.AZURE_SECRET_CALLBACK_HANDLER;
import static org.wso2.carbon.securevault.azure.commons.Constants.CRLF_SANITATION_REGEX;
import static org.wso2.carbon.securevault.azure.commons.Constants.VERSION_DELIMITER;
import static org.wso2.carbon.securevault.azure.repository.SecretClientFactory.getSecretClient;

/**
 * Extension to facilitate the use of an Azure Key Vault as an external secret repository.
 */
public class AzureSecretRepository implements SecretRepository {

    private static final Log log = LogFactory.getLog(AzureSecretRepository.class);
    private static final String ALGORITHM = "algorithm";
    private static final String DEFAULT_ALGORITHM = "RSA";
    private static final String CONFIG_ENCRYPTION_ENABLED = "encryptionEnabled";
    private static final String SECRET_NAME_REGEX = "^[a-zA-Z0-9-]*$";
    private Boolean encryptionEnabled = false;
    private DecryptionProvider baseCipher;
    private SecretRepository parentRepository;
    private IdentityKeyStoreWrapper identityKeyStoreWrapper;
    private TrustKeyStoreWrapper trustKeyStoreWrapper;
    private ConfigUtils configUtils;
    private SecretClient secretClient;

    /**
     * Creates an AzureSecretRepository by setting the identity keystore wrapper and trust keystore wrapper with
     * identityKeyStoreWrapper and trustKeyStoreWrapper, respectively.
     *
     * @param identityKeyStoreWrapper Identity keystore wrapper.
     * @param trustKeyStoreWrapper Trust keystore wrapper.
     */
    public AzureSecretRepository(IdentityKeyStoreWrapper identityKeyStoreWrapper,
                                 TrustKeyStoreWrapper trustKeyStoreWrapper) {

        this.identityKeyStoreWrapper = identityKeyStoreWrapper;
        this.trustKeyStoreWrapper = trustKeyStoreWrapper;
    }

    /**
     * Constructor with no parameters to be used with the novel configuration of Carbon Secure Vault.
     */
    public AzureSecretRepository() {
    }

    /**
     * Initializes the Key Vault as a Secret Repository.
     *
     * @param properties Configuration properties from file.
     * @param id Identifier to identify properties related to the corresponding repository.
     */
    @Override
    public void init(Properties properties, String id) {

        try {
            /*
            - The secrets related to retrieved through the AzureSecretCallbackHandler would not involve any
            encryption/decryption as the keystores (used for encryption/decryption) would not have been initialized
            at that point.
            - Therefore, when this method is called from the mentioned handler, the following if block is skipped and
            encryption is not enabled even if the encryptionEnabled configuration is set to true.
            - Prior to retrieving the secrets defined in the deployment.toml file, this method would be called again
            from the Carbon Secure Vault core, during which the following if block would be executed and the encryption
            status would be set according to the value specified in the encryptionEnabled configuration.
             */
            if (!AZURE_SECRET_CALLBACK_HANDLER.equals(id)) {
                configUtils = ConfigUtils.getInstance();
                encryptionEnabled = Boolean.parseBoolean(configUtils.getAzureSecretRepositoryConfig(properties,
                        CONFIG_ENCRYPTION_ENABLED));
                if (encryptionEnabled) {
                    initDecryptionProvider(properties);
                }
            }
            secretClient = getSecretClient(properties);
        } catch (AzureSecretRepositoryException e) {
            log.error("Failed to initialize secret repository.", e);
        }
    }

    /**
     * Retrieves a secret from the Key Vault and, if encryption has been enabled,
     * decrypts the retrieved value before returning it.
     *
     * @param alias The name and version (the latter is optional) of the secret being retrieved.
     * @return The secret corresponding to the alias from the Key Vault. If not found, returns an empty String.
     */
    @Override
    public String getSecret(String alias) {

        /* If no secret was retrieved, an empty String would be returned. If a runtime exception is thrown,
        secret retrieval is attempted repeatedly in a loop for secrets like the keystore password, which would prevent
        moving on to the next step or the server breaking.*/
        String secret = StringUtils.EMPTY;
        try {
            secret = retrieveSecretFromVault(alias);
        } catch (AzureSecretRepositoryException e) {
            log.error("Secret retrieval failed.", e);
        }
        if (StringUtils.isNotEmpty(secret)) {
            if (log.isDebugEnabled()) {
                log.debug("Secret with reference '" + alias.replaceAll(CRLF_SANITATION_REGEX, StringUtils.EMPTY)
                        + "' was successfully retrieved from Azure Key Vault.");
            }
            /*
            If secrets were encrypted with the cipher tool prior to storing them in the Key Vault, they would be
            decrypted in the following if block and the plain text value of the secret would be returned.
            */
            if (encryptionEnabled) {
                secret = new String(baseCipher.decrypt(secret.trim().getBytes(StandardCharsets.UTF_8)),
                        StandardCharsets.UTF_8);
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved secret was successfully decrypted.");
                }
            }
        } else {
            String aliasToLog = StringUtils.isEmpty(alias) ? "empty reference" : ("reference '" + alias + "'");
            log.error("Failed to retrieve secret with " + aliasToLog.replaceAll(CRLF_SANITATION_REGEX,
                    StringUtils.EMPTY) + ". Value set to empty String.");
        }
        return secret;
    }

    /**
     * Gets the encrypted value of the secret corresponding to the alias.
     *
     * @return encrypted value of secret stored in Key Vault if encryption has been enabled.
     */
    @Override
    public String getEncryptedData(String alias) {

        if (encryptionEnabled) {
            try {
                return retrieveSecretFromVault(alias);
            } catch (AzureSecretRepositoryException e) {
                log.error("Retrieval of encrypted data of secret with reference '" +
                        alias.replaceAll(CRLF_SANITATION_REGEX, StringUtils.EMPTY) + "' from Azure Key Vault failed. " +
                        "Returning empty String.");
                return StringUtils.EMPTY;
            }
        } else {
            throw new UnsupportedOperationException("Encryption has not been enabled.");
        }
    }

    /**
     * Sets the parent repository. Allows secret repositories to be set in a chain
     * so that one repository can get secrets from another.
     */
    @Override
    public void setParent(SecretRepository parent) {

        this.parentRepository = parent;
    }

    /**
     * Gets the parent repository.
     *
     * @return Parent repository.
     */
    @Override
    public SecretRepository getParent() {

        return this.parentRepository;
    }

    /**
     * Initializes the DecryptionProvider to be used if encryption has been enabled.
     *
     * @param properties Configuration properties from file.
     */
    private void initDecryptionProvider(Properties properties) throws AzureSecretRepositoryException {

        if (identityKeyStoreWrapper == null) {
            throw new AzureSecretRepositoryException("Failed to initialize decryption provider. Keystore has not been" +
                    " initialized.");
        }
        String algorithm = configUtils.getAzureSecretRepositoryConfig(properties, ALGORITHM);
        if (StringUtils.isEmpty(algorithm)) {
            if (log.isDebugEnabled()) {
                log.debug("No algorithm configured. Using default value: " + DEFAULT_ALGORITHM);
            }
            algorithm = DEFAULT_ALGORITHM;
        }
        KeyStoreWrapper keyStoreWrapper = identityKeyStoreWrapper;
        CipherInformation cipherInformation = new CipherInformation();
        cipherInformation.setAlgorithm(algorithm);
        cipherInformation.setCipherOperationMode(CipherOperationMode.DECRYPT);
        cipherInformation.setInType(EncodingType.BASE64);
        baseCipher = CipherFactory.createCipher(cipherInformation, keyStoreWrapper);
    }

    /**
     * Retrieves a secret from the Key Vault according to the specified version.
     * If a secret version has not been specified, the latest version is retrieved.
     *
     * @param alias The name and version (the latter is optional) of the secret being retrieved.
     * @return the secret value retrieved from the Key Vault.
     */
    private String retrieveSecretFromVault(String alias) throws AzureSecretRepositoryException {

        String secretValue = StringUtils.EMPTY;
        if (secretClient != null) {
            SecretReference secretReference = parseSecretReference(alias);
            if (!secretReference.secretName.matches(SECRET_NAME_REGEX)) {
                throw new AzureSecretRepositoryException("Invalid secret name: " +
                        secretReference.secretName.replaceAll(CRLF_SANITATION_REGEX, StringUtils.EMPTY) + ". Azure " +
                        "Key Vault secret names can only contain alphanumeric characters and dashes.");
            }
            if (log.isDebugEnabled()) {
                if (StringUtils.isNotEmpty(secretReference.secretVersion)) {
                    log.debug("Secret version '" + secretReference.secretVersion.replaceAll(CRLF_SANITATION_REGEX,
                            StringUtils.EMPTY) + "' found for secret '" + secretReference.secretName.replaceAll(
                            CRLF_SANITATION_REGEX, StringUtils.EMPTY) + "'. Retrieving specified version of secret.");
                } else {
                    log.debug("Secret version not found for secret '" + alias.replaceAll(CRLF_SANITATION_REGEX,
                            StringUtils.EMPTY) + "'. Retrieving latest version of secret.");
                }
            }
            try {
                secretValue = secretClient.getSecret(secretReference.secretName,
                        secretReference.secretVersion).getValue();
            } catch (ResourceNotFoundException e) {
                throw new AzureSecretRepositoryException("Secret not found in Key Vault.", e);
            }
        }
        return secretValue;
    }

    /**
     * Parses a secret reference into the secret's name and version.
     *
     * @param alias The secret reference comprising the name and version (the latter is optional)
     *              of the secret being retrieved.
     * @return An array comprising the name and version of the secret.
     * @throws AzureSecretRepositoryException If parsing of the secret reference failed.
     */
    private SecretReference parseSecretReference(String alias) throws AzureSecretRepositoryException {

        if (StringUtils.isNotEmpty(alias)) {
            if (alias.contains(VERSION_DELIMITER)) {
                if (StringUtils.countMatches(alias, VERSION_DELIMITER) == 1) {
                    String[] aliasComponents = alias.split(VERSION_DELIMITER, -1);
                    if (StringUtils.isEmpty(aliasComponents[0])) {
                        throw new AzureSecretRepositoryException("Secret name cannot be empty.");
                    }
                    return new SecretReference(aliasComponents[0], aliasComponents[1]);
                } else {
                    throw new AzureSecretRepositoryException("Syntax error in secret reference '" + alias.replaceAll(
                            CRLF_SANITATION_REGEX, StringUtils.EMPTY) + "'. Secret reference should be in the format" +
                            " 'secretName" + VERSION_DELIMITER + "secretVersion'. Note that there should be only one" +
                            " " + VERSION_DELIMITER + ".");
                }
            }
            return new SecretReference(alias);
        } else {
            throw new AzureSecretRepositoryException("Secret alias cannot be empty.");
        }
    }

    /**
     * Sets the identity key store wrapper and trust key store wrapper.
     *
     * @param identityKeyStoreWrapper The identity key store wrapper to be set.
     * @param trustKeyStoreWrapper The trust key store wrapper to be set.
     */
    public void setKeyStores(IdentityKeyStoreWrapper identityKeyStoreWrapper,
                             TrustKeyStoreWrapper trustKeyStoreWrapper) {

        this.identityKeyStoreWrapper = identityKeyStoreWrapper;
        this.trustKeyStoreWrapper = trustKeyStoreWrapper;
    }

    /**
     * Class to model a secret reference.
     */
    private static class SecretReference {

        private String secretName;
        private String secretVersion;

        public SecretReference(String secretName) {
            this.secretName = secretName;
        }

        public SecretReference(String secretName, String secretVersion) {
            this.secretName = secretName;
            this.secretVersion = secretVersion;
        }
    }
}
