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

import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import org.wso2.securevault.secret.SecretRepositoryProvider;

/**
 * Provides an Azure Key Vault based secret repository.
 */
public class AzureSecretRepositoryProvider implements SecretRepositoryProvider {

    /**
     * Gets a new instance of AzureSecretRepository.
     *
     * @param identityKeyStoreWrapper Identity Keystore
     * @param trustKeyStoreWrapper Trust Keystore
     * @return A SecretRepository object.
     */
    @Override
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identityKeyStoreWrapper,
                                                TrustKeyStoreWrapper trustKeyStoreWrapper) {
        return new AzureSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);
    }
}
