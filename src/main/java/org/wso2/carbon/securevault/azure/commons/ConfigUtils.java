/**
 * Copyright (c) 2022, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.securevault.azure.commons;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Properties;

import static org.wso2.carbon.securevault.azure.commons.Constants.AZURE;
import static org.wso2.carbon.securevault.azure.commons.Constants.CONFIG_FILE;
import static org.wso2.carbon.securevault.azure.commons.Constants.CRLF_SANITATION_REGEX;
import static org.wso2.carbon.securevault.azure.commons.Constants.LEGACY_CONFIG_PREFIX;
import static org.wso2.carbon.securevault.azure.commons.Constants.NOVEL_CONFIG_PREFIX;
import static org.wso2.carbon.securevault.azure.commons.Constants.SECRET_REPOSITORIES;

/**
 * Config Utils class to read the configurations from the
 * secret-conf.properties file as well as environment variables.
 */
public class ConfigUtils {

    private static final Log log = LogFactory.getLog(ConfigUtils.class);
    private static String propertyPrefix;
    private static ConfigUtils instance;

    /**
     * Gets the instance of the ConfigUtils class.
     *
     * @return Instance of ConfigUtils.
     */
    public static synchronized ConfigUtils getInstance() {

        if (instance == null) {
            instance = new ConfigUtils();
        }
        return instance;
    }

    /**
     * Gets a configuration; first, it is attempted to read the value from the secret-conf.properties file.
     * If a value is not found in the file, it is attempted to read the value from environment variables.
     *
     * @param properties   Configuration properties from the secret-conf.properties file.
     * @param configName   The name of the configuration property.
     * @return The value of the configuration property.
     */
    @SuppressFBWarnings(value = "CRLF_INJECTION_LOGS")
    public String getAzureSecretRepositoryConfig(Properties properties, String configName) {

        String configValue = properties.getProperty(readConfigPrefix(properties) + configName);
        if (StringUtils.isNotEmpty(configValue)) {
            if (log.isDebugEnabled()) {
                log.debug("Using " + configName.replaceAll(CRLF_SANITATION_REGEX, StringUtils.EMPTY) + " found in " +
                        CONFIG_FILE + " file.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug(configName.replaceAll(CRLF_SANITATION_REGEX, StringUtils.EMPTY) + " not found in " +
                        CONFIG_FILE + " file. Checking environment variables.");
            }
            configValue = getConfigFromEnvironmentVariables(configName);
        }
        if (StringUtils.isNotEmpty(configValue)) {
            configValue = configValue.trim();
        }
        return configValue;
    }

    /**
     * Reads a configuration property from environment variables.
     *
     * @param configName   The name of the configuration property.
     * @return The value of the configuration property.
     */
    @SuppressFBWarnings(value = "CRLF_INJECTION_LOGS")
    private String getConfigFromEnvironmentVariables(String configName) {

        String configValue = System.getenv(AZURE + StringUtils.capitalize(configName));
        if (StringUtils.isNotEmpty(configValue)) {
            if (log.isDebugEnabled()) {
                log.debug("Using " + configName.replaceAll(CRLF_SANITATION_REGEX, StringUtils.EMPTY) +
                        " found as an environment variable.");
            }
            return configValue;
        }
        if (log.isDebugEnabled()) {
            log.debug(configName.replaceAll(CRLF_SANITATION_REGEX, StringUtils.EMPTY) + " not found as an " +
                    "environment variable.");
        }
        return configValue;
    }

    /**
     * Reads whether the configuration used is of the legacy or novel type and sets the prefix accordingly.
     *
     * @param properties Configuration properties from the secret-conf.properties file.
     * @return The property prefix used in the secret-conf.properties file.
     */
    private static String readConfigPrefix(Properties properties) {

        if (StringUtils.isEmpty(propertyPrefix)) {
            /*
            - With the legacy configuration, a property called "secretRepositories" is used to specify the type of
            secret repository to be used (example: "azure") and is the prefix for the rest of the properties.

            - With the novel configuration, since multiple secret repositories may be used based on the provider, the
            provider type must be specified first using a property called "secretProviders" (example: "vault") and is
            the prefix for the rest of the properties.
            */
            String legacyProvidersString = properties.getProperty(SECRET_REPOSITORIES);
            if (StringUtils.isNotEmpty(legacyProvidersString)) {
                if (log.isDebugEnabled()) {
                    log.debug("Legacy provider found. Using legacy configurations.");
                }
                propertyPrefix = LEGACY_CONFIG_PREFIX;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Legacy provider not found. Using novel configurations.");
                }
                propertyPrefix = NOVEL_CONFIG_PREFIX;
            }
        }
        return propertyPrefix;
    }
}
