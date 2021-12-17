package cmd

import (
	"context"
	"net"

	"github.com/hupe1980/log4shellscan/internal"
	"github.com/spf13/cobra"
)

func newCatchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "catch [caddr]",
		Short:                 "Start a callback catcher",
		Args:                  cobra.MinimumNArgs(1),
		SilenceUsage:          true,
		DisableFlagsInUseLine: true,

		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			caddr := args[0]

			catcher, err := internal.NewCallBackCatcher("tcp", caddr)
			if err != nil {
				return err
			}
			defer catcher.Close()

			catcher.Handler(func(addr *net.TCPAddr) {
				printDanger("Possibly vulnerable host identified: %v:%d", addr.IP.String(), addr.Port)
			})

			printInfo("Listening on %s", caddr)

			if err := catcher.Listen(ctx); err != nil {
				return err
			}

			return nil
		},
	}

	return cmd
}
