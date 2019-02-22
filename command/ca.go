package command

import (
	"fmt"

	"github.com/yawn/cvsig/certificate"
	"github.com/yawn/cvsig/sync"
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{

	Use:   "setup",
	Short: "Generates server and ca certificates",
	Long:  "Generates CA keychain and exports it for usage in Lambda with encrypted private key, generates signed server keypair and exports it into ACM",
	RunE: func(cmd *cobra.Command, args []string) error {

		ca, err := certificate.NewCA("OpenVPN CA") // TODO: configurable (domain name)

		if err != nil {
			return err
		}

		server, err := certificate.NewServer(ca, "OpenVPN Server") // TODO: configurable (domain name)

		if err != nil {
			return err
		}

		export := sync.Export{
			KeyID:  "1dcee528-7b7c-43f9-b2af-42dba0245e59", // TODO: configurable
			Region: "eu-west-1",                            // TODO: configurable
		}

		// TODO: split this in streams / configurable
		id, err := export.ExportServer(ca, server)

		if err != nil {
			return err
		}

		fmt.Println(*id)

		// TODO: split this in streams / configurable
		chain, secret, err := export.ExportCA(ca)

		if err != nil {
			return err
		}

		fmt.Println(string(*chain))
		fmt.Println(string(*secret))

		imp := &sync.Import{
			Region: "eu-west-1",
		}

		cert, err := imp.ImportCA(*chain, *secret)

		if err != nil {
			return err
		}

		fmt.Println(cert)

		return nil

	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
}
