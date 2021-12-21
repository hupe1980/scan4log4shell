package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/hupe1980/log4shellscan/internal"
	"github.com/spf13/cobra"
)

func newCatchCmd() *cobra.Command {
	var (
		caddr string
	)

	cmd := &cobra.Command{
		Use:                   "catch [tcp | dns]",
		Short:                 "Start a callback catcher",
		Args:                  cobra.MinimumNArgs(1),
		SilenceUsage:          true,
		DisableFlagsInUseLine: true,

		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			catcherType := strings.ToLower(args[0])

			catcher, err := newCatcher(catcherType, caddr)
			if err != nil {
				return err
			}

			defer catcher.Close()

			catcher.Handler(func(remoteAddr, resource string) {
				printDanger("Possibly vulnerable host identified: %v/%s", remoteAddr, resource)
			})

			printInfo("Listening on %s", catcher.Addr())

			if err := catcher.Listen(ctx); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&caddr, "caddr", "", "", "address to catch the callbacks (eg. ip:port)")

	return cmd
}

func newCatcher(catcherType, caddr string) (internal.CallbackCatcher, error) {
	switch catcherType {
	case "tcp":
		catcher, err := internal.NewTCPCallBackCatcher("tcp", caddr)
		if err != nil {
			return nil, err
		}

		return catcher, nil
	case "ldap":
		catcher, err := internal.NewLDAPCatcher(caddr)
		if err != nil {
			return nil, err
		}

		return catcher, nil
	case "dns":
		addr := "interact.sh"
		if caddr != "" {
			addr = caddr
		}

		catcher, err := internal.NewInteractsh(addr)

		if err != nil {
			return nil, err
		}

		return catcher, nil
	default:
		return nil, fmt.Errorf("unknown catcher type %s", catcherType)
	}
}
