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

package org.wso2.carbon.securevault.azure.exception;

/**
 * Exception thrown when an Azure Key Vault is used as an external
 * secret repository and errors occur.
 */
public class AzureSecretRepositoryException extends Exception {

    /**
     * Constructs a new exception with the specified detail message.
     *
     * @param message The detail message for the exception.
     */
    public AzureSecretRepositoryException(String message) {
        super(message);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * @param message The detail message for the exception.
     * @param cause   The cause of the exception.
     */
    public AzureSecretRepositoryException(String message, Throwable cause) {
        super(message, cause);
    }
}
