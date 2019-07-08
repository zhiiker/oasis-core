package common

import (
	"fmt"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/common/committee"
	"github.com/oasislabs/ekiden/go/worker/common/p2p"
)

// Runtime is a single runtime.
type Runtime struct {
	id signature.PublicKey

	node *committee.Node
}

// GetNode returns the committee node for this runtime.
func (r *Runtime) GetNode() *committee.Node {
	if r == nil {
		return nil
	}
	return r.node
}

// Worker is a garbage bag with lower level services and common runtime objects.
type Worker struct {
	enabled bool
	cfg     Config

	Identity  *identity.Identity
	Storage   storage.Backend
	Roothash  roothash.Backend
	Registry  registry.Backend
	Scheduler scheduler.Backend
	Consensus common.ConsensusBackend
	Grpc      *grpc.Server
	P2P       *p2p.P2P

	runtimes map[signature.MapKey]*Runtime

	quitCh chan struct{}
	initCh chan struct{}

	logger *logging.Logger
}

// Name returns the service name.
func (w *Worker) Name() string {
	return "txnscheduler worker"
}

// Start starts the service.
func (w *Worker) Start() error {
	if !w.enabled {
		w.logger.Info("not starting common worker as it is disabled")

		// In case the worker is not enabled, close the init channel immediately.
		close(w.initCh)

		return nil
	}

	// Wait for the gRPC server and all runtimes to terminate.
	go func() {
		defer close(w.quitCh)

		for _, rt := range w.runtimes {
			<-rt.node.Quit()
		}

		<-w.Grpc.Quit()
	}()

	// Wait for all runtimes to be initialized.
	go func() {
		for _, rt := range w.runtimes {
			<-rt.node.Initialized()
		}

		close(w.initCh)
	}()

	// Start runtime services.
	for _, rt := range w.runtimes {
		w.logger.Info("starting services for runtime",
			"runtime_id", rt.id,
		)

		if err := rt.node.Start(); err != nil {
			return err
		}
	}

	return nil
}

// Stop halts the service.
func (w *Worker) Stop() {
	if !w.enabled {
		close(w.quitCh)
		return
	}

	for _, rt := range w.runtimes {
		w.logger.Info("stopping services for runtime",
			"runtime_id", rt.id,
		)

		rt.node.Stop()
	}

	w.Grpc.Stop()
}

// Enabled returns if worker is enabled.
func (w *Worker) Enabled() bool {
	return w.enabled
}

// Quit returns a channel that will be closed when the service terminates.
func (w *Worker) Quit() <-chan struct{} {
	return w.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (w *Worker) Cleanup() {
	if !w.enabled {
		return
	}

	for _, rt := range w.runtimes {
		rt.node.Cleanup()
	}

	w.Grpc.Cleanup()
}

// Initialized returns a channel that will be closed when the transaction scheduler is
// initialized and ready to service requests.
func (w *Worker) Initialized() <-chan struct{} {
	return w.initCh
}

// GetConfig returns the worker's configuration.
func (w *Worker) GetConfig() Config {
	return w.cfg
}

// GetRuntime returns a registered runtime.
//
// In case the runtime with the specified id was not registered it
// returns nil.
func (w *Worker) GetRuntime(id signature.PublicKey) *Runtime {
	rt, ok := w.runtimes[id.ToMapKey()]
	if !ok {
		return nil
	}

	return rt
}

func (w *Worker) registerRuntime(cfg *Config, id signature.PublicKey) error {
	w.logger.Info("registering new runtime",
		"runtime_id", id,
	)

	node, err := committee.NewNode(
		id,
		w.Identity,
		w.Storage,
		w.Roothash,
		w.Registry,
		w.Scheduler,
		w.Consensus,
		w.P2P,
	)
	if err != nil {
		return err
	}

	rt := &Runtime{
		id:   id,
		node: node,
	}
	w.runtimes[rt.id.ToMapKey()] = rt

	w.logger.Info("new runtime registered",
		"runtime_id", rt.id,
	)

	return nil
}

func newWorker(
	enabled bool,
	identity *identity.Identity,
	storage storage.Backend,
	roothash roothash.Backend,
	registryInst registry.Backend,
	scheduler scheduler.Backend,
	consensus common.ConsensusBackend,
	grpc *grpc.Server,
	p2p *p2p.P2P,
	cfg Config,
) (*Worker, error) {
	w := &Worker{
		enabled:   enabled,
		cfg:       cfg,
		Identity:  identity,
		Storage:   storage,
		Roothash:  roothash,
		Registry:  registryInst,
		Scheduler: scheduler,
		Consensus: consensus,
		Grpc:      grpc,
		P2P:       p2p,
		runtimes:  make(map[signature.MapKey]*Runtime),
		quitCh:    make(chan struct{}),
		initCh:    make(chan struct{}),
		logger:    logging.GetLogger("worker/common"),
	}

	if enabled {
		if len(cfg.Runtimes) == 0 {
			return nil, fmt.Errorf("common/worker: no runtimes configured")
		}

		// Register all configured runtimes.
		for _, id := range cfg.Runtimes {
			if err := w.registerRuntime(&cfg, id); err != nil {
				return nil, err
			}
		}
	}

	return w, nil
}

// New creates a new worker.
func New(
	enabled bool,
	identity *identity.Identity,
	storage storage.Backend,
	roothash roothash.Backend,
	registry registry.Backend,
	scheduler scheduler.Backend,
	consensus common.ConsensusBackend,
	p2p *p2p.P2P,
) (*Worker, error) {
	cfg, err := newConfig()
	if err != nil {
		return nil, err
	}

	// Create externally-accessible gRPC server.
	grpc, err := grpc.NewServerTCP("external", cfg.ClientPort, identity.TLSCertificate, nil)
	if err != nil {
		return nil, err
	}

	return newWorker(enabled, identity, storage, roothash, registry, scheduler, consensus, grpc, p2p, *cfg)
}
