package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/hupe1980/log4shellscan/internal"
	"github.com/spf13/cobra"
)

func newCatchCmd() *cobra.Command {
	var (
		caddr string
	)

	cmd := &cobra.Command{
		Use:   "catch [tcp | dns | ldap]",
		Short: "Start a standalone callback catcher",
		Args:  cobra.MinimumNArgs(1),
		Example: `- Start a standalone dns catcher: scan4log4shell catch dns
- Start a standalone ldap catcher: scan4log4shell catch ldap --caddr 127.0.0.1:4444
- Start a standalone tcp catcher: scan4log4shell catch tcp --caddr 127.0.0.1:4444`,
		SilenceUsage:  true,
		SilenceErrors: true,

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

			go func() {
				if err := catcher.Listen(ctx); err != nil {
					printError("cannot start %s callback catcher: %s", catcherType, err)
					os.Exit(1)
				}
			}()

			signalChan := make(chan os.Signal, 1)
			signal.Notify(signalChan, os.Interrupt)

			<-signalChan

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
