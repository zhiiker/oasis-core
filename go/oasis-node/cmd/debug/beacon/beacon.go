// Package beacon implements the beacon introspection debug sub-commands.
package beacon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
)

var (
	beaconCmd = &cobra.Command{
		Use:   "beacon",
		Short: "debug the random beacon",
	}

	beaconStatusCmd = &cobra.Command{
		Use:   "status",
		Short: "query beacon status",
		Run:   doBeaconStatus,
	}

	logger = logging.GetLogger("cmd/debug/beacon")
)

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, beacon.Backend) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := beacon.NewBeaconClient(conn)

	return conn, client
}

func doBeaconStatus(cmd *cobra.Command, args []string) {
	conn, client := doConnect(cmd)
	defer conn.Close()

	logger.Info("querying latest beacon")

	b, err := client.GetBeacon(context.Background(), consensus.HeightLatest)
	if err != nil {
		logger.Error("failed to query beacon",
			"err", err,
		)
		os.Exit(1)
	}

	// I'm going to be sad if people use this as a way to programatically
	// scrape the beacon.  Oh well.
	prettyOut := struct {
		Beacon []byte
		State  *beacon.PVSSState
	}{
		Beacon: b,
	}

	pvssClient, ok := client.(beacon.PVSSBackend)
	if ok {
		prettyOut.State, err = pvssClient.GetPVSSState(context.Background(), consensus.HeightLatest)
		if err != nil {
			logger.Error("failed to query PVSS backend state",
				"err", err,
			)
			os.Exit(1)
		}
	}

	formatted, err := json.MarshalIndent(prettyOut, "", "  ")
	if err != nil {
		logger.Error("failed to format state",
			"err", err,
		)
		os.Exit(1)
	}
	fmt.Println(string(formatted))
}

// Register registers the beacon sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	beaconCmd.PersistentFlags().AddFlagSet(cmdGrpc.ClientFlags)

	beaconCmd.AddCommand(beaconStatusCmd)
	parentCmd.AddCommand(beaconCmd)
}
