package azkeyvault

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"go.k6.io/k6/secretsource"
)

func newAzureKeyVaultFromParams(params secretsource.Params) (secretsource.Source, error) {
	vaultURL := params.ConfigArgument

	// Acquire a DefaultAzureCredential (will use VM managed identity if available)
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azkeyvault: failed to obtain credential: %w", err)
	}

	// Create the Key Vault secrets client
	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azkeyvault: failed to create client: %w", err)
	}

	return &azureKeyVaultSource{client: client, vaultURL: vaultURL}, nil
}

type azureKeyVaultSource struct {
	client   *azsecrets.Client
	vaultURL string
}

// Description appears in k6’s CLI help
func (s *azureKeyVaultSource) Description() string {
	return fmt.Sprintf("Azure Key Vault (vault: %s)", s.vaultURL)
}

func (s *azureKeyVaultSource) Get(key string) (string, error) {
	ctx := context.Background()

	resp, err := s.client.GetSecret(ctx, key, "", nil)

	if err != nil {
		return "", fmt.Errorf("azkeyvault: getting secret %q failed: %w", key, err)
	}

	if resp.Value == nil {
		return "", fmt.Errorf("azkeyvault: secret %q has nil value", key)
	}

	return *resp.Value, nil
}

func init() {
	// Register the plugin under the name "azkeyvault"
	secretsource.RegisterExtension("azkeyvault", newAzureKeyVaultFromParams)
}
