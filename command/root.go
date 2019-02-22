package command

import (
	"github.com/yawn/cvsig/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var conf config.Config

var rootCmd = &cobra.Command{
	Use:           app,
	SilenceErrors: true,
	SilenceUsage:  true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {

		if err := viper.Unmarshal(&conf); err != nil {
			return err
		}

		return conf.Init()

	},
	RunE: func(cmd *cobra.Command, args []string) error {

		// run lambda

		return nil

	},
}

func init() {

	flag(rootCmd.PersistentFlags(),
		false,
		"verbose",
		"v",
		"CVPN_VERBOSE",
		"enable verbose logging",
	)

}
