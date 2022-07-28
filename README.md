# Carbon Secure Vault Extension for Azure Key Vault

Carbon Secure Vault extension to use an Azure Key Vault as an external secret repository.

## Getting Started

This steps to be followed to insert and use extension with the Identity Server are given below.

- [Step 1: Building and Inserting the Azure Extension into the Identity Server](#step-1-building-and-inserting-the-azure-extension-into-the-identity-server)
- [Step 2: Enabling Carbon Secure Vault](#step-2-enabling-carbon-secure-vault)
- [Step 3: Setting up Authentication to Azure Key Vault](#step-3-setting-up-authentication-to-azure-key-vault)
  - [Environment Credentials](#environment-credentials)
  - [Managed Identities](#managed-identities)
  - [Azure CLI](#azure-cli)
  - [Default Azure Credential Chain](#default-azure-credential-chain)
  - [Service Principal with Secret: Credentials Provided via Files](#service-principal-with-secret-credentials-provided-via-files)
- [Step 4: Referencing Deployment Secrets](#step-4-referencing-deployment-secrets)
- [Step 5: Providing the Carbon Secure Vault Root Password](#step-5-providing-the-carbon-secure-vault-root-password)
  - [Entering in the Command Line](#entering-in-the-command-line)
  - [Reading from a File within the Identity Server](#reading-from-a-file-within-the-identity-server)
  - [Retrieving from Azure Key Vault](#retrieving-from-azure-key-vault)

Besides the basic set up and usage of the extension, the extension also has the following capabilities.

 - [Using Multiple External Secret Repositories](#using-multiple-external-secret-repositories)
 - [Combining the Internal File-Based Secret Repository with Azure Key Vault as the External Secret Repository](#combining-the-internal-file-based-secret-repository-with-azure-key-vault-as-the-external-secret-repository)
 - [Retrieving the Carbon Secure Vault Root Password from Azure Key Vault with Non-Azure-Based Secret Repositories](#retrieving-the-carbon-secure-vault-root-password-from-azure-key-vault-with-non-azure-based-secret-repositories)
 - [Debugging](#debugging)

## Step 1: Building and Inserting the Azure Extension into the Identity Server

1. Clone this project onto your computer or download it as a zip and unzip it.
2. Run `mvn clean install` from the `carbon-securevault-azure` directory to build the OSGi bundle for the extension.
3. Copy this bundle, the `org.wso2.carbon.securevault.azure-1.0.jar` file, from the `target` directory within the project.
4. Insert the bundle within the Identity Server by pasting it into the `dropins` directory (`<IS_HOME>/repository/components/dropins`).

<p align="right">(<a href="#carbon-secure-vault-extension-for-azure-key-vault">↑ Return to the Top</a>)</p>

## Step 2: Enabling Carbon Secure Vault

There are 2 ways of configuring the secret repository. Namely, the legacy and novel configuration.

The legacy configuration was the only available configuration prior to IS 6.0.0, which introduced the novel configuration in addition to the existing legacy configuration. The configurations are done as described below.

1. Add the following lines to the `secret-conf.properties` Carbon Secure Vault configuration file (`<IS_HOME>/repository/conf/security/secret-conf.properties`) according to whether you are using the novel or legacy configuration.

    - **Novel:**

      ```
      carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
      secVault.enabled=true
      secretProviders=vault
      secretProviders.vault.provider=org.wso2.securevault.secret.repository.VaultSecretRepositoryProvider
      secretProviders.vault.repositories=azure
      secretProviders.vault.repositories.azure=org.wso2.carbon.securevault.azure.repository.AzureSecretRepository
      secretProviders.vault.repositories.azure.properties.keyVaultName=<name-of-the-azure-key-vault>
      secretProviders.vault.repositories.azure.properties.credentialType=<choice-of-authentication-credential>
      ```

    - **Legacy:**

      ```
      keystore.identity.location=repository/resources/security/wso2carbon.jks
      keystore.identity.type=JKS
      keystore.identity.alias=wso2carbon
      keystore.identity.store.password=identity.store.password
      keystore.identity.store.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
      keystore.identity.key.password=identity.key.password
      keystore.identity.key.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
      carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
      secVault.enabled=true
      secretRepositories=azure
      secretRepositories.azure.provider=org.wso2.carbon.securevault.azure.repository.AzureSecretRepositoryProvider
      secretRepositories.azure.properties.keyVaultName=<name-of-the-azure-key-vault>
      secretRepositories.azure.properties.credentialType=<choice-of-authentication-credential>
      ```

    Note that if the legacy configuration is used, the keystore configurations starting with `keystore.` mentioned above are mandatory regardless of whether the keystore is used by Carbon Secure Vault secrets or not. 
    
    Additionally, the keystore password will have to be provided as described in [Step 5: Carbon Secure Vault Root Password](#step-5-carbon-secure-vault-root-password) when the server starts up.

2. Edit the last two lines of either configuration according to your Key Vault and authentication preference;
    - `keyVaultName`: the name of the Key Vault which is to be used as a secret repository. You may also choose to set this value as an environment variable named `azureKeyVaultName` instead of adding it here.
    - `credentialType`: the credential to be used to authenticate to the Key Vault. You may also choose to set this value as an environment variable named `azureCredentialType` instead of adding it here. See [Step 3: Setting Up Authentication to Azure Key Vault](#step-3-setting-up-authentication-to-azure-key-vault) for further details on the options available.

**Note that if the value of a configuration has been set both in the configuration file and as an environment variable, the value set in the configuration file is given priority and will be the one that is used.**

<p align="right">(<a href="#carbon-secure-vault-extension-for-azure-key-vault">↑ Return to the Top</a>)</p>

## Step 3: Setting up Authentication to Azure Key Vault

There are 5 types of authentication credentials that may be used and it is necessary to specify the choice of credential type either as a configuration property named `credentialType` or an environment variable named `azureCredentialType` as mentioned in [Step 2: Enabling Carbon Secure Vault](#step-2-enabling-carbon-secure-vault).

### Environment Credentials
- Set the credential type configuration value as `env`.
- See the Microsoft Documentation regarding [Authentication via Environment Variables](https://docs.microsoft.com/en-us/azure/developer/java/sdk/identity-azure-hosted-auth#environment-variables) for further information.

### Managed Identities
- Set the credential type configuration value as `mi`.
- If you choose to authenticate via a user-assigned managed identity, the managed identity's client id can be set as a configuration property named `managedIdentityClientId` or an environment variable named `azureManagedIdentityClientId`.
   
   ```
   #If the novel configuration is used:
   secretProviders.vault.repositories.azure.properties.managedIdentityClientId=<client-id-of-user-assigned-managed-identity>
   ```
   
   ```
   #If the legacy configuration is used:
   secretRepositories.azure.properties.managedIdentityClientId=<client-id-of-user-assigned-managed-identity>
   ```
- See the Microsoft Documentation on [Managed Identities](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) for further information.

### Azure CLI
- Set the credential type configuration value as `cli`.
- See the Microsoft Documentation on [Azure CLI](https://docs.microsoft.com/en-us/azure/developer/java/sdk/identity-dev-env-auth#azure-cli-credential) for further information.

### Default Azure Credential Chain
- Set the credential type configuration value as `chain`.
- The Default Azure Credential Chain supports authentication through environment variables, managed identities, IDE-specific credentials and the Azure CLI in the given order. If no value is set for the type of credential, authentication is attempted via this chain by default.
- See the Microsoft Documentation on the [Default Azure Credential Chain](https://docs.microsoft.com/en-us/azure/developer/java/sdk/identity-azure-hosted-auth#default-azure-credential) for further information.

### Service Principal with Secret: Credentials Provided via Files
- Set the credential type configuration value as `file`.
- Provide the Azure AD application's client secret in the first line of a file and specify the path to this file either as a configuration property named `clientSecretFilePath` in the `secret-conf.properties` file or as an environment variable named `azureClientSecretFilePath`.
- Provide the Azure AD application's client id and tenant id either as configuration properties named `clientId` and `tenantId` in the `secret-conf.properties` file or as environment variables named `azureClientId` and `azureTenantId`.
  ```
  #If the novel configuration is used:
  secretProviders.vault.repositories.azure.properties.clientId=<client-id>
  secretProviders.vault.repositories.azure.properties.clientSecretFilePath=<path-to-file-containing-the-client-secret>
  secretProviders.vault.repositories.azure.properties.tenantId=<tenant-id>
  ```
  
  ```
  #If the legacy configuration is used:
  secretRepositories.azure.properties.clientId=<client-id>
  secretRepositories.azure.properties.clientSecretFilePath=<path-to-file-containing-the-client-secret>
  secretRepositories.azure.properties.tenantId=<tenant-id>
  ```

<p align="right">(<a href="#carbon-secure-vault-extension-for-azure-key-vault">↑ Return to the Top</a>)</p>

## Step 4: Referencing Deployment Secrets

1. In the `deployment.toml` file (`<IS_HOME>/repository/conf/deployment.toml`), replace each value to be provided as a secret with a reference.

    - **To retrieve the latest version of a secret (default):** set the reference using an alias in the format `$secret{secretName}` with the name of the secret in your Key Vault.
    - **To retrieve a specific version of a secret:** set the reference in the format `$secret{secretName_secretVersion}` with the name and version of the secret in your Key Vault.


    Example:
      
      ```
      [super_admin]
      username = "admin"
      password = "admin"
      create_admin_account = true
      ```

      If the password in the above is stored in the user's Key Vault as a secret with the name `admin-password`, the configuration would be updated as follows.

      ```
      [super_admin]
      username = "admin"
      password = "$secret{admin-password}" #retrieves the latest version of the secret
      create_admin_account = true
      
      #or
      
      [super_admin]
      username = "admin"
      password = "$secret{admin-password_xxxxx}" #retrieves version xxxxx of the secret
      create_admin_account = true
      ```

2. Next, according to your version of the Identity Server, add another section to the `deployment.toml` file.

    - **IS 6.0.0 onwards:**
    - 
      ```
      [runtime_secrets]
      enable = "true"
      ```

    - **IS 5.11.0 and below:**

      ```
      [secrets]
      secretReference1 = ""
      secretReference2 = ""
      secretReference3 = ""
      ```
      Where the above is a list of the secret references.

      Based on the example given in the previous step, it would be as follows.
      
      ```
      [secrets]
      admin-password = “”
      
      #or 
      
      [secrets]
      admin-password_xxxxx = “”
      ```

<p align="right">(<a href="#carbon-secure-vault-extension-for-azure-key-vault">↑ Return to the Top</a>)</p>

## Step 5: Providing the Carbon Secure Vault Root Password 

If you are using the legacy configuration or if you are using the novel configuration with encryption enabled as described in [Combining the Internal File-Based Secret Repository with Azure Key Vault as the External Secret Repository](#combining-the-internal-file-based-secret-repository-with-azure-key-vault-as-the-external-secret-repository), when you start the server, you will be required to provide the keystore password and private key password, which is `wso2carbon` by default.

However, if you are using the novel configurations without the use of the keystore for additional encryption, this step is not necessary and you are all set to use your Key Vault with the Identity Server's Carbon Secure Vault. [Return to the top](#carbon-secure-vault-extension-for-azure-key-vault) to explore the other capabilities of this extension with Carbon Secure Vault.

The keystore and private key password may be provided in one of the following ways.
- [Entering in the Command Line](#entering-in-the-command-line)
- [Reading from a File within the Identity Server](#reading-from-a-file-within-the-identity-server)
- [Retrieving from Azure Key Vault](#retrieving-from-azure-key-vault)

### Entering in the Command Line

If the keystore password and primary key password are not provided via either of the other options, you will be prompted to enter the value(s) via the command line, where you may then enter it manually.

`[Enter KeyStore and Private Key Password: ]`

However, this is not possible when you run the server as a background job, so we could instead save the value(s) elsewhere and have it automatically read as mentioned in methods 2 and 3.

### Reading from a File within the Identity Server

Create a file in the `<IS_HOME>` directory and name it as described below.

- If you wish to have the file deleted automatically after the server starts, the file name should have `tmp` (i.e., temporary) in it as follows.

  > For Linux: The file name should be `password-tmp`.
  >
  > For Windows: The file name should be `password-tmp.txt`.

- Alternatively, if you wish to retain the password file after the server starts so that the same file can be used in subsequent deployments as well, the file name should have `persist` (i.e., persistent) as follows.

  >For Linux: The file name should be `password-persist`.
  >
  >For Windows: The file name should be `password-persist.txt`.

Note that, by default, both the private key password and keystore password are assumed to be the same and the value is provided in the first line of the file. However, if they are not the same, the keystore password and private key password must be provided in the first and second lines of the file, respectively.

### Retrieving from Azure Key Vault

1. Create a secret and store your password(s) in your Key Vault.
2. Edit the configurations in the `secret-conf.properties` file mentioned in [Step 2: Enabling Carbon Secure Vault](#step-2-enabling-carbon-secure-vault) as follows.
    1. Replace the values for the two properties `keystore.identity.store.secretProvider` and `keystore.identity.key.secretProvider` with `org.wso2.carbon.securevault.azure.handler.AzureSecretCallbackHandler`. This is the fully qualified class path of the Azure Key Vault Secret Callback Handler, which we will be using instead of the Default Secret Callback Handler that supports [Reading from a File within the Identity Server](reading-from-a-file-within-the-identity-server].
    2. Provide the secret references for your password(s) in the format `secretName` or `secretName_secretVersion` as described in [Step 4: Referencing Deployment Secrets](#step-4-referencing-deployment-secrets) using the configurations given below.
         ```
         keystore.identity.store.alias=<keystore-password-secret-reference>
         keystore.identity.key.alias=<private-key-password-secret-reference>
         ```
       If both the keystore and private key passwords are the same, only provide the keystore password secret reference configuration. However, if they are not, provide the secret reference of the private key password as well.

The first half of your configuration file would now be as follows.
```
keystore.identity.location=repository/resources/security/wso2carbon.jks
keystore.identity.type=JKS
keystore.identity.alias=wso2carbon
keystore.identity.store.password=identity.store.password
keystore.identity.store.alias=<alias-and-version-of-password>
keystore.identity.store.secretProvider=org.wso2.carbon.securevault.azure.handler.AzureSecretCallbackHandler
keystore.identity.key.password=identity.key.password
keystore.identity.key.secretProvider=org.wso2.carbon.securevault.azure.handler.AzureSecretCallbackHandler
keystore.identity.key.alias=<alias-and-version-of-password>
```

That's it! Now you're ready to use your Key Vault as a secret repository with the Identity Server's Carbon Secure Vault. [Return to the top](#carbon-secure-vault-extension-for-azure-key-vault) to explore the other capabilities of this extension with Carbon Secure Vault.

<p align="right">(<a href="#carbon-secure-vault-extension-for-azure-key-vault">↑ Return to the Top</a>)</p>

## Using Multiple External Secret Repositories

The steps given above describe setting up an Azure Key Vault as your only secret repository. However, from Identity Server 6.0.0 onwards, the use of multiple secret repositories is supported as well. This means you can store and retrieve your Identity Server secrets from various vaults if you wish to, such as from an Azure Key Vault and AWS Secrets Manager.

To use multiple external secret repositories in this manner, the novel configurations mentioned in [Step 2: Enabling Carbon Secure Vault](#step-2-enabling-carbon-secure-vault) must be used.

The steps to set this up are as follows.

1. Edit the novel configurations as given below by adding the relevant values as stated.

   ```
   carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
   secVault.enabled=true
   secretProviders=vault
   secretProviders.vault.provider=org.wso2.securevault.secret.repository.VaultSecretRepositoryProvider
   secretProviders.vault.repositories=azure,<other-repository-type>
   secretProviders.vault.repositories.azure=org.wso2.carbon.securevault.azure.repository.AzureSecretRepository
   secretProviders.vault.repositories.azure.properties.keyVaultName=<name-of-the-azure-key-vault>
   secretProviders.vault.repositories.azure.properties.credential=<choice-of-authentication-credential>
   secretProviders.vault.repositories.azure.properties.managedIdentityClientId=<client-id-of-user-assigned-managed-identity> #optional
   secretProviders.vault.repositories.<other-repository-type>=<fully-qualified-classpath-of-the-other-repository>
   secretProviders.vault.repositories.<other-repository-type>.properties.<property-name>=<property-value>
   ```

2. In the `deployment.toml` file mentioned in [Step 4: Referencing Deployment Secrets](#step-4-referencing-deployment-secrets), the secret references should be in the format `$secret{provider:repository:secretReference}`. For example, your Key Vault secret references would be `$secret{vault:azure:superAdminPassword}`, while your other repository references would be `$secret{vault:<other-repository-type>:superAdminPassword}`.

For Azure Key Vault, the secret reference may be `secretName` or `secretName_secretVersion` as described in [Step 4: Referencing Deployment Secrets](#step-4-referencing-deployment-secrets). For other vaults, the secret reference will have to be configured according to the other vault's supported secret reference configuration.

<p align="right">(<a href="#carbon-secure-vault-extension-for-azure-key-vault">↑ Return to the Top</a>)</p>

## Combining the Internal File-Based Secret Repository with Azure Key Vault as the External Secret Repository

The extension supports adding an extra layer of security by allowing the internal file-based secret repository to be used in conjunction with your Key Vault. This could be done as follows.

1. Encrypt and store your secrets within the keystore in the Identity Server using the cipher tool. This could be done by following the steps described in [Encrypting Passwords with Cipher Tool](https://is.docs.wso2.com/en/latest/setup/encrypting-passwords-with-cipher-tool/) in the WSO2 Identity Server documentation or as given below.
   - Navigate to the `<IS_HOME>/bin` directory and execute the following command via your command line according to your operating system.

     > For Linux: ./ciphertool.sh
     >
     > For Windows: ciphertool.bat

   - Enter the internal keystore password upon being prompted.
   - Enter the plain-text value of your secret as prompted, which would return the encrypted secret data.
3. Store the encrypted secret data obtained through the above step in your Key Vault instead of the plain-text values.
4. Configure the extension for use with the Identity Server as describe previously.
5. Add an additional configuration called `encyrptionEnabled` in the `secret-conf.properties` file and set it to `true`.

   ```
   #If the novel configuration is used:
   secretProviders.vault.repositories.azure.properties.encryptionEnabled=true
   ```
   
   ```
   #If the legacy configuration is used:
   secretRepositories.azure.properties.encryptionEnabled=true
   ```
   If the legacy configuration is used, encryption may instead be enabled by setting an environment variable named `azureEncryptionEnabled` to true as well.
   
5. If the novel configuration is used with encryption enabled, the keystore configurations listed in [Step 2: Enabling Carbon Secure Vault](#step-2-enabling-carbon-secure-vault) need to be added. Your `secret-conf.properties` file would then be as follows.

   ```
   keystore.identity.location=repository/resources/security/wso2carbon.jks
   keystore.identity.type=JKS
   keystore.identity.alias=wso2carbon
   keystore.identity.store.password=identity.store.password
   keystore.identity.store.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
   keystore.identity.key.password=identity.key.password
   keystore.identity.key.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
   carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
   secVault.enabled=true
   secretProviders=vault
   secretProviders.vault.provider=org.wso2.securevault.secret.repository.VaultSecretRepositoryProvider
   secretProviders.vault.repositories=azure
   secretProviders.vault.repositories.azure=org.wso2.carbon.securevault.azure.repository.AzureSecretRepository
   secretProviders.vault.repositories.azure.properties.keyVaultName=<name-of-the-azure-key-vault>
   secretProviders.vault.repositories.azure.properties.credentialType=<choice-of-authentication-credential>
   secretProviders.vault.repositories.azure.properties.managedIdentityClientId=<client-id-of-user-assigned-managed-identity> #optional
   secretProviders.vault.repositories.azure.properties.encryptionEnabled=true
   ```
6. Provide the Carbon Secure Vault root password by following [Step 5: Carbon Secure Vault Root Password](#step-5-carbon-secure-vault-root-password) when you start the server.

Note that if encryption is enabled in this manner, all secrets except the Carbon Secure Vault root password must be encrypted as the extension would attempt to decrypt each value prior to returning the secret values.
  
<p align="right">(<a href="#carbon-secure-vault-extension-for-azure-key-vault">↑ Return to the Top</a>)</p>

## Retrieving the Carbon Secure Vault Root Password from Azure Key Vault with Non-Azure-Based Secret Repositories

If you do not wish to use Azure Key Vault for your deployment secrets specified in the `deployment.toml` file, but wish to use it to provide the Carbon Secure Vault root password, it is possible to do so by using the Azure Secret Callback Handler in this extension as a standalone feature.

This can be done as given below.

1. Configure and set up the non-Azure-based secret repository of your choice.
2. Follow Steps 1-5 mentioned [at the top](#carbon-secure-vault-extension-for-azure-key-vault) with the exclusion of [Step 4: Referencing Deployment Secrets](#step-4-referencing-deployment-secrets) and a modification to [Step 2: Enabling Carbon Secure Vault](#step-2-enabling-carbon-secure-vault) as described below.
3. [Step 2: Enabling Carbon Secure Vault](#step-2-enabling-carbon-secure-vault) involves configuring Carbon Secure Vault and the secret repository to be used, which we have already done when configuring and setting up the non-Azure-based secret repository as stated above. The only additional properties required to be configured in this step are the Key Vault name and credential type.
4. When following [Step 5: Providing the Carbon Secure Vault Root Password](#step-5-providing-the-carbon-secure-vault-root-password), ensure you pick the 3rd option [Retrieving from Azure Key Vault](#retrieving-from-azure-key-vault) as that is where we configure the Azure Secret Callback Handler.

<p align="right">(<a href="#carbon-secure-vault-extension-for-azure-key-vault">↑ Return to the Top</a>)</p>

## Debugging

1. For debug logs, add the following lines to the `log4j2.properties` file (`<IS_HOME>\repository\conf\log4j2.properties`).

   ```
   logger.org-wso2-carbon-securevault-azure.name=org.wso2.carbon.securevault.azure
   logger.org-wso2-carbon-securevault-azure.level=DEBUG
   logger.org-wso2-carbon-securevault-azure.additivity=false
   logger.org-wso2-carbon-securevault-azure.appenderRef.CARBON_CONSOLE.ref = CARBON_CONSOLE
   ```

2. Then add `org-wso2-carbon-securevault-azure` to the list of loggers as follows.

   ```
   loggers = AUDIT_LOG, trace-messages, ..., org-wso2-carbon-securevault-azure
   ```
   
<p align="right">(<a href="#carbon-secure-vault-extension-for-azure-key-vault">↑ Return to the Top</a>)</p>
