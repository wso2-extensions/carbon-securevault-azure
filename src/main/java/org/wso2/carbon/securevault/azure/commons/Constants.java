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

/**
 * Class to define the public constants used.
 */
public class Constants {

    public static final String AZURE = "azure";
    public static final String CONFIG_FILE = "secret-conf.properties";
    public static final String DOT = ".";
    public static final String AZURE_SECRET_CALLBACK_HANDLER = "azureSecretCallbackHandler";
    public static final String KEY = "key";
    public static final String PROPERTIES = "properties";
    public static final String REPOSITORIES = "repositories";
    public static final String SECRET_PROVIDERS = "secretProviders";
    public static final String SECRET_REPOSITORIES = "secretRepositories";
    public static final String CRLF_SANITATION_REGEX = "[\r\n]";
    public static final String STORE = "store";
    public static final String VAULT = "vault";
    public static final String VERSION_DELIMITER = "_";
    public static final String NOVEL_CONFIG_PREFIX = SECRET_PROVIDERS + DOT + VAULT + DOT + REPOSITORIES + DOT +
            AZURE + DOT + PROPERTIES + DOT;
    public static final String LEGACY_CONFIG_PREFIX = SECRET_REPOSITORIES + DOT + AZURE + DOT + PROPERTIES + DOT;
}
