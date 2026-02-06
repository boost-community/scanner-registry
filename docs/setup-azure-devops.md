# Azure DevOps Test Runner Setup

## 1. Create Test Runner Repository

1. Create a new repository named `scan-test-runner-azure-devops` in your Azure DevOps project
2. Add the pipeline configuration at `azure-pipelines.yml`
3. Create a pipeline from the YAML file

---

## 2. Register Microsoft Entra ID Application

1. Navigate to Azure Portal:
   **Microsoft Entra ID → App registrations → New registration**

   Direct link: https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/CreateApplicationBlade

2. Configure the application:

   | Field                       | Value                                          |
   |-----------------------------|------------------------------------------------|
   | **Name**                    | `BoostSecurity.io Scan Test Runner`            |
   | **Supported account types** | Accounts in this organizational directory only |
   | **Redirect URI**            | Leave blank                                    |

3. Click **Register**

4. Note the **Application (client) ID** and **Directory (tenant) ID** from the overview page

---

## 3. Add Federated Credential for GitHub Actions pull request from the same repository

1. In the app registration, go to:
   **Certificates & secrets → Federated credentials → Add credential**

2. Select **GitHub Actions deploying Azure resources**

3. Configure the federated credential:
   Need to be done for both
   - boostsecurityio/dev-registry
   - boost-community/scanner-registry
   
   | Field                  | Value               |
   |------------------------|---------------------|
   | **Organization**       | <org name>          |
   | **Repository**         | <repo name>         |
   | **Entity type**        | Pull Request        |
   | **Name**               | `github-actions-pr` |

4. Click **Add**

---

## 4. Add Federated Credential for GitHub Actions pull request from forks

1. In the app registration, go to:
   **Certificates & secrets → Federated credentials → Add credential**

2. Select **GitHub Actions deploying Azure resources**

3. Configure the federated credential:
   Need to be done for both
   - boostsecurityio/dev-registry
   - boost-community/scanner-registry
   
   | Field            | Value                          |
   |------------------|--------------------------------|
   | **Organization** | <org name>                     |
   | **Repository**   | <repo name>                    |
   | **Entity type**  | Environement                   |
   | **Value**        | scan-test                      |
   | **Name**         | `github-actions-<env>-pr-fork` |

4. Click **Add**

---

## 5. Grant Permissions in Azure DevOps

1. Navigate to your Azure DevOps organization:
   **Organization Settings → Users → Add users**

   Or: `https://dev.azure.com/{ORG}/_settings/users`

2. Add the service principal:
   - Search for the app name: `BoostSecurity.io Scan Test Runner`
   - Access level: **Basic**
   - Add to project: Select your project

3. Navigate to project permissions:
   **Project Settings → Permissions → {Your Project} Team → Members → Add**

4. Add the service principal with **Build Administrator** role (or create a custom role with Build: Read & Execute)

---

## 6. Configure Secrets on Scanner Registry Repository

Navigate to the scanner registry repository (GitHub):
**Settings → Secrets and variables → Actions → New repository secret**

| Secret Name                       | Value                               |
|-----------------------------------|-------------------------------------|
| `BOOST_SCAN_RUNNER_ADO_TENANT_ID` | Directory (tenant) ID from step 2   |
| `BOOST_SCAN_RUNNER_ADO_CLIENT_ID` | Application (client) ID from step 2 |


---

## 7. Usage in GitHub Actions Workflow

```yaml
permissions:
  id-token: write  # Required for OIDC
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.BOOST_SCAN_RUNNER_ADO_CLIENT_ID }}
          tenant-id: ${{ secrets.BOOST_SCAN_RUNNER_ADO_TENANT_ID }}
          allow-no-subscriptions: true

      - name: Get Azure DevOps Token
        id: azure-token
        run: |
          token=$(az account get-access-token \
            --resource 499b84ac-1321-427f-aa17-267ca6975798 \
            --query accessToken -o tsv)
          echo "token=$token" >> $GITHUB_OUTPUT
          echo "::add-mask::$token"

      - name: Run test-action
        ...
```

---

## 8. Token Details

| Property             | Value                                |
|----------------------|--------------------------------------|
| **Lifetime**         | ~1 hour                              |
| **Refresh**          | New token generated per workflow run |
| **Secrets Required** | None (OIDC federation)               |

---

## References

- [Configure OIDC for GitHub Actions and Azure](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-azure)
- [Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
- [Azure DevOps REST API Authentication](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/service-principal-managed-identity)
- [azure/login GitHub Action](https://github.com/Azure/login)
