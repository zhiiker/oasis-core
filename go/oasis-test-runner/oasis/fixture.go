package oasis

import (
	"fmt"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

// NetworkFixture describes configuration for the test Oasis network and
// all the spawned nodes.
type NetworkFixture struct {
	TEE                TEEFixture                `json:"tee,omitempty"`
	Network            NetworkCfg                `json:"network,omitempty"`
	Entities           []EntityCfg               `json:"entities,omitempty"`
	Runtimes           []RuntimeFixture          `json:"runtimes,omitempty"`
	Validators         []ValidatorFixture        `json:"validators,omitempty"`
	Keymanagers        []KeymanagerFixture       `json:"keymanagers,omitempty"`
	KeymanagerPolicies []KeymanagerPolicyFixture `json:"keymanager_policies,omitempty"`
	StorageWorkers     []StorageWorkerFixture    `json:"storage_workers,omitempty"`
	ComputeWorkers     []ComputeWorkerFixture    `json:"compute_workers,omitempty"`
	Sentries           []SentryFixture           `json:"sentries,omitempty"`
	Clients            []ClientFixture           `json:"clients,omitempty"`
	Seeds              []SeedFixture             `json:"seeds,omitempty"`
	ByzantineNodes     []ByzantineFixture        `json:"byzantine_nodes,omitempty"`
}

// Create instantiates the network described by the fixture.
func (f *NetworkFixture) Create(env *env.Env) (*Network, error) {
	// Use default MRSIGNER if not provided.
	if f.TEE.Hardware == node.TEEHardwareIntelSGX && f.TEE.MrSigner == nil {
		f.TEE.MrSigner = &sgx.FortanixDummyMrSigner
	}

	// Create the top level Oasis network.
	var net *Network
	var err error
	if net, err = New(env, &f.Network); err != nil {
		return nil, err
	}

	// Ensure the creation order here is good enough for proper startup in
	// net.Start, since that'll just iterate through node objects.

	// Provision entities.
	for _, entCfg := range f.Entities {
		if _, err = net.NewEntity(&entCfg); err != nil { // nolint: gosec
			return nil, fmt.Errorf("failed to provision entity: %w", err)
		}
	}

	// Provision runtimes.
	for _, fx := range f.Runtimes {
		if _, err = fx.Create(f, net); err != nil {
			return nil, err
		}
	}

	// Provision the sentry nodes.
	for _, fx := range f.Sentries {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	for _, fx := range f.Seeds {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	// Provision validators.
	for _, fx := range f.Validators {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	// Provision key manager policies.
	for _, fx := range f.KeymanagerPolicies {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	// Provision key managers.
	for _, fx := range f.Keymanagers {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	// Provision the storage workers.
	for _, fx := range f.StorageWorkers {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	// Provision the compute workers.
	for _, fx := range f.ComputeWorkers {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	// Provision the client nodes.
	for _, fx := range f.Clients {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	// Provision the Byzantine nodes.
	for _, fx := range f.ByzantineNodes {
		if _, err = fx.Create(net); err != nil {
			return nil, err
		}
	}

	return net, nil
}

// ConsensusFixture is a fixture containing consensus-related configuration.
type ConsensusFixture struct { // nolint: maligned
	// MinGasPrice specifies the minimum gas price accepted by a validator node.
	MinGasPrice uint64 `json:"min_gas_price"`
	// SubmissionGasPrice is the gas price to use when submitting consensus transactions.
	SubmissionGasPrice uint64 `json:"submission_gas_price"`

	// PruneNumKept is the number of blocks to keep (zero disables pruning).
	PruneNumKept uint64 `json:"prune_num_kept"`

	// TendermintRecoverCorruptedWAL enables automatic recovery of corrupted Tendermint's WAL.
	TendermintRecoverCorruptedWAL bool `json:"tendermint_recover_corrupted_wal"`

	// EnableConsensusRPCWorker enables the public consensus RPC services worker.
	EnableConsensusRPCWorker bool `json:"enable_consensusrpc_worker,omitempty"`

	// SupplementarySanityInterval configures the sanity check application.
	SupplementarySanityInterval uint64 `json:"supplementary_sanity_interval,omitempty"`
}

// NodeFixture is a common subset of settings for node-backed fixtures.
type NodeFixture struct {
	// Name is the name of the node that hosts the feature. Leave empty
	// to automatically instantiate a dedicated node with a default name.
	Name string `json:"node_name,omitempty"`

	ExtraArgs []Argument `json:"extra_args,omitempty"`
}

// TEEFixture is a TEE configuration fixture.
type TEEFixture struct {
	Hardware node.TEEHardware `json:"hardware"`
	MrSigner *sgx.MrSigner    `json:"mr_signer"`
}

// ValidatorFixture is a validator fixture.
type ValidatorFixture struct { // nolint: maligned
	NodeFixture

	AllowEarlyTermination bool `json:"allow_early_termination"`
	AllowErrorTermination bool `json:"allow_error_termination"`

	NoAutoStart bool `json:"no_auto_start,omitempty"`

	CrashPointsProbability float64 `json:"crash_points_probability,omitempty"`

	EnableProfiling bool `json:"enable_profiling"`

	Entity int `json:"entity"`

	LogWatcherHandlerFactories []log.WatcherHandlerFactory `json:"-"`

	Sentries []int `json:"sentries,omitempty"`

	// Consensus contains configuration for the consensus backend.
	Consensus ConsensusFixture `json:"consensus"`
}

// Create instantiates the validator described by the fixture.
func (f *ValidatorFixture) Create(net *Network) (*Validator, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}
	sentries, err := resolveSentries(net, f.Sentries)
	if err != nil {
		return nil, err
	}

	return net.NewValidator(&ValidatorCfg{
		NodeCfg: NodeCfg{
			Name:                        f.Name,
			AllowEarlyTermination:       f.AllowEarlyTermination,
			AllowErrorTermination:       f.AllowErrorTermination,
			LogWatcherHandlerFactories:  f.LogWatcherHandlerFactories,
			Consensus:                   f.Consensus,
			NoAutoStart:                 f.NoAutoStart,
			CrashPointsProbability:      f.CrashPointsProbability,
			SupplementarySanityInterval: f.Consensus.SupplementarySanityInterval,
			EnableProfiling:             f.EnableProfiling,
			Entity:                      entity,
			ExtraArgs:                   f.ExtraArgs,
		},
		Sentries: sentries,
	})
}

// RuntimeFixture is a runtime fixture.
type RuntimeFixture struct { // nolint: maligned
	ID         common.Namespace     `json:"id"`
	Kind       registry.RuntimeKind `json:"kind"`
	Entity     int                  `json:"entity"`
	Keymanager int                  `json:"keymanager"`

	Binaries         map[node.TEEHardware][]string `json:"binaries"`
	GenesisState     storage.WriteLog              `json:"genesis_state,omitempty"`
	GenesisStatePath string                        `json:"genesis_state_path,omitempty"`
	GenesisRound     uint64                        `json:"genesis_round,omitempty"`

	Executor     registry.ExecutorParameters     `json:"executor"`
	TxnScheduler registry.TxnSchedulerParameters `json:"txn_scheduler"`
	Storage      registry.StorageParameters      `json:"storage"`

	AdmissionPolicy registry.RuntimeAdmissionPolicy                                               `json:"admission_policy"`
	Constraints     map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints `json:"constraints,omitempty"`
	Staking         registry.RuntimeStakingParameters                                             `json:"staking,omitempty"`

	GovernanceModel registry.RuntimeGovernanceModel `json:"governance_model"`

	Pruner RuntimePrunerCfg `json:"pruner,omitempty"`

	ExcludeFromGenesis bool `json:"exclude_from_genesis,omitempty"`
}

// Create instantiates the runtime described by the fixture.
func (f *RuntimeFixture) Create(netFixture *NetworkFixture, net *Network) (*Runtime, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}

	var km *Runtime
	if f.Keymanager != -1 {
		switch f.Kind {
		case registry.KindCompute:
			if km, err = resolveRuntimeOfKind(net, f.Keymanager, registry.KindKeyManager); err != nil {
				return nil, err
			}
		case registry.KindKeyManager:
			return nil, fmt.Errorf("key manager runtime cannot have a key manager")
		}
	}

	return net.NewRuntime(&RuntimeCfg{
		ID:                 f.ID,
		Kind:               f.Kind,
		Entity:             entity,
		Keymanager:         km,
		TEEHardware:        netFixture.TEE.Hardware,
		MrSigner:           netFixture.TEE.MrSigner,
		Executor:           f.Executor,
		TxnScheduler:       f.TxnScheduler,
		Storage:            f.Storage,
		AdmissionPolicy:    f.AdmissionPolicy,
		Staking:            f.Staking,
		Binaries:           f.Binaries,
		GenesisState:       f.GenesisState,
		GenesisStatePath:   f.GenesisStatePath,
		GenesisRound:       f.GenesisRound,
		Pruner:             f.Pruner,
		ExcludeFromGenesis: f.ExcludeFromGenesis,
		GovernanceModel:    f.GovernanceModel,
	})
}

// KeymangerPolicyFixgure is a key manager policy fixture.
type KeymanagerPolicyFixture struct {
	Runtime int `json:"runtime"`
	Serial  int `json:"serial"`
}

// Create instantiates the key manager policy described in the fixture.
func (f *KeymanagerPolicyFixture) Create(net *Network) (*KeymanagerPolicy, error) {
	runtime, err := resolveRuntimeOfKind(net, f.Runtime, registry.KindKeyManager)
	if err != nil {
		return nil, err
	}

	return net.NewKeymanagerPolicy(&KeymanagerPolicyCfg{
		Runtime: runtime,
		Serial:  f.Serial,
	})
}

// KeymanagerFixture is a key manager fixture.
type KeymanagerFixture struct {
	NodeFixture

	Runtime int `json:"runtime"`
	Entity  int `json:"entity"`
	Policy  int `json:"policy"`

	RuntimeProvisioner string `json:"runtime_provisioner"`

	AllowEarlyTermination bool `json:"allow_early_termination"`
	AllowErrorTermination bool `json:"allow_error_termination"`

	NoAutoStart bool `json:"no_auto_start,omitempty"`

	EnableProfiling bool `json:"enable_profiling"`

	Sentries []int `json:"sentries,omitempty"`

	// Consensus contains configuration for the consensus backend.
	Consensus ConsensusFixture `json:"consensus"`

	CrashPointsProbability float64 `json:"crash_points_probability,omitempty"`

	LogWatcherHandlerFactories []log.WatcherHandlerFactory `json:"-"`
}

// Create instantiates the key manager described by the fixture.
func (f *KeymanagerFixture) Create(net *Network) (*Keymanager, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}
	runtime, err := resolveRuntimeOfKind(net, f.Runtime, registry.KindKeyManager)
	if err != nil {
		return nil, err
	}
	policy, err := resolveKMPolicy(net, f.Policy)
	if err != nil {
		return nil, err
	}

	return net.NewKeymanager(&KeymanagerCfg{
		NodeCfg: NodeCfg{
			Name:                        f.Name,
			AllowEarlyTermination:       f.AllowEarlyTermination,
			AllowErrorTermination:       f.AllowErrorTermination,
			LogWatcherHandlerFactories:  f.LogWatcherHandlerFactories,
			CrashPointsProbability:      f.CrashPointsProbability,
			SupplementarySanityInterval: f.Consensus.SupplementarySanityInterval,
			EnableProfiling:             f.EnableProfiling,
			Consensus:                   f.Consensus,
			NoAutoStart:                 f.NoAutoStart,
			Entity:                      entity,
			ExtraArgs:                   f.ExtraArgs,
		},
		RuntimeProvisioner: f.RuntimeProvisioner,
		Runtime:            runtime,
		Policy:             policy,
		SentryIndices:      f.Sentries,
	})
}

// StorageWorkerFixture is a storage worker fixture.
type StorageWorkerFixture struct { // nolint: maligned
	NodeFixture

	Backend string `json:"backend"`
	Entity  int    `json:"entity"`

	AllowEarlyTermination bool `json:"allow_early_termination"`
	AllowErrorTermination bool `json:"allow_error_termination"`

	NoAutoStart bool `json:"no_auto_start,omitempty"`

	EnableProfiling bool `json:"enable_profiling"`

	DisableCertRotation bool `json:"disable_cert_rotation"`
	DisablePublicRPC    bool `json:"disable_public_rpc"`

	LogWatcherHandlerFactories []log.WatcherHandlerFactory `json:"-"`

	Sentries []int `json:"sentries,omitempty"`

	// Consensus contains configuration for the consensus backend.
	Consensus ConsensusFixture `json:"consensus"`

	CheckpointCheckInterval time.Duration `json:"checkpoint_check_interval,omitempty"`
	IgnoreApplies           bool          `json:"ignore_applies,omitempty"`
	CheckpointSyncEnabled   bool          `json:"checkpoint_sync_enabled,omitempty"`

	CrashPointsProbability float64 `json:"crash_points_probability,omitempty"`

	// Runtimes contains the indexes of the runtimes to enable. Leave
	// empty or nil for the default behaviour (i.e. include all runtimes).
	Runtimes []int `json:"runtimes,omitempty"`
}

// Create instantiates the storage worker described by the fixture.
func (f *StorageWorkerFixture) Create(net *Network) (*Storage, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}

	return net.NewStorage(&StorageCfg{
		NodeCfg: NodeCfg{
			Name:                        f.Name,
			AllowEarlyTermination:       f.AllowEarlyTermination,
			AllowErrorTermination:       f.AllowErrorTermination,
			CrashPointsProbability:      f.CrashPointsProbability,
			SupplementarySanityInterval: f.Consensus.SupplementarySanityInterval,
			EnableProfiling:             f.EnableProfiling,
			NoAutoStart:                 f.NoAutoStart,
			LogWatcherHandlerFactories:  f.LogWatcherHandlerFactories,
			Consensus:                   f.Consensus,
			Entity:                      entity,
			ExtraArgs:                   f.ExtraArgs,
		},
		Backend:                 f.Backend,
		SentryIndices:           f.Sentries,
		CheckpointCheckInterval: f.CheckpointCheckInterval,
		IgnoreApplies:           f.IgnoreApplies,
		// The checkpoint syncing flag is intentionally flipped here.
		// Syncing should normally be enabled, but normally disabled in tests.
		CheckpointSyncDisabled: !f.CheckpointSyncEnabled,
		DisableCertRotation:    f.DisableCertRotation,
		DisablePublicRPC:       f.DisablePublicRPC,
		Runtimes:               f.Runtimes,
	})
}

// ComputeWorkerFixture is a compute worker fixture.
type ComputeWorkerFixture struct {
	NodeFixture

	Entity int `json:"entity"`

	RuntimeProvisioner string `json:"runtime_provisioner"`

	AllowEarlyTermination bool `json:"allow_early_termination"`
	AllowErrorTermination bool `json:"allow_error_termination"`

	NoAutoStart bool `json:"no_auto_start,omitempty"`

	EnableProfiling bool `json:"enable_profiling"`

	// Consensus contains configuration for the consensus backend.
	Consensus ConsensusFixture `json:"consensus"`

	CrashPointsProbability float64 `json:"crash_point_probability"`

	LogWatcherHandlerFactories []log.WatcherHandlerFactory `json:"-"`

	// Runtimes contains the indexes of the runtimes to enable.
	Runtimes []int `json:"runtimes,omitempty"`

	// RuntimeConfig contains the per-runtime node-local configuration.
	RuntimeConfig map[int]map[string]interface{} `json:"runtime_config,omitempty"`
}

// Create instantiates the compute worker described by the fixture.
func (f *ComputeWorkerFixture) Create(net *Network) (*Compute, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}

	return net.NewCompute(&ComputeCfg{
		NodeCfg: NodeCfg{
			Name:                        f.Name,
			AllowEarlyTermination:       f.AllowEarlyTermination,
			AllowErrorTermination:       f.AllowErrorTermination,
			NoAutoStart:                 f.NoAutoStart,
			CrashPointsProbability:      f.CrashPointsProbability,
			SupplementarySanityInterval: f.Consensus.SupplementarySanityInterval,
			EnableProfiling:             f.EnableProfiling,
			LogWatcherHandlerFactories:  f.LogWatcherHandlerFactories,
			Consensus:                   f.Consensus,
			Entity:                      entity,
			ExtraArgs:                   f.ExtraArgs,
		},
		RuntimeProvisioner: f.RuntimeProvisioner,
		Runtimes:           f.Runtimes,
		RuntimeConfig:      f.RuntimeConfig,
	})
}

// SeedFixture is a seed node fixture.
type SeedFixture struct {
	NodeFixture

	DisableAddrBookFromGenesis bool `json:"disable_addr_book_from_genesis"`
}

// Create instantiates the seed node described by the fixture.
func (f *SeedFixture) Create(net *Network) (*Seed, error) {
	return net.NewSeed(&SeedCfg{
		Name:                       f.Name,
		DisableAddrBookFromGenesis: f.DisableAddrBookFromGenesis,
	})
}

// SentryFixture is a sentry node fixture.
type SentryFixture struct {
	NodeFixture

	LogWatcherHandlerFactories []log.WatcherHandlerFactory `json:"-"`

	CrashPointsProbability float64 `json:"crash_points_probability,omitempty"`

	EnableProfiling bool `json:"enable_profiling"`

	// Consensus contains configuration for the consensus backend.
	Consensus ConsensusFixture `json:"consensus"`

	Validators        []int `json:"validators"`
	StorageWorkers    []int `json:"storage_workers"`
	KeymanagerWorkers []int `json:"keymanager_workers"`
}

// Create instantiates the sentry node described by the fixture.
func (f *SentryFixture) Create(net *Network) (*Sentry, error) {
	return net.NewSentry(&SentryCfg{
		NodeCfg: NodeCfg{
			Name:                        f.Name,
			LogWatcherHandlerFactories:  f.LogWatcherHandlerFactories,
			CrashPointsProbability:      f.CrashPointsProbability,
			SupplementarySanityInterval: f.Consensus.SupplementarySanityInterval,
			EnableProfiling:             f.EnableProfiling,
			ExtraArgs:                   f.ExtraArgs,
		},
		ValidatorIndices:  f.Validators,
		StorageIndices:    f.StorageWorkers,
		KeymanagerIndices: f.KeymanagerWorkers,
	})
}

// ClientFixture is a client node fixture.
type ClientFixture struct {
	NodeFixture

	AllowErrorTermination bool `json:"allow_error_termination"`
	AllowEarlyTermination bool `json:"allow_early_termination"`

	EnableProfiling bool `json:"enable_profiling"`

	// Consensus contains configuration for the consensus backend.
	Consensus ConsensusFixture `json:"consensus"`

	// Runtimes contains the indexes of the runtimes to enable.
	Runtimes []int `json:"runtimes,omitempty"`

	RuntimeProvisioner string `json:"runtime_provisioner"`

	// RuntimeConfig contains the per-runtime node-local configuration.
	RuntimeConfig map[int]map[string]interface{} `json:"runtime_config,omitempty"`

	// MaxTransactionAge configures the MaxTransactionAge configuration of the client.
	MaxTransactionAge int64 `json:"max_transaction_age"`
}

// Create instantiates the client node described by the fixture.
func (f *ClientFixture) Create(net *Network) (*Client, error) {
	return net.NewClient(&ClientCfg{
		NodeCfg: NodeCfg{
			Name:                        f.Name,
			Consensus:                   f.Consensus,
			AllowErrorTermination:       f.AllowErrorTermination,
			AllowEarlyTermination:       f.AllowEarlyTermination,
			SupplementarySanityInterval: f.Consensus.SupplementarySanityInterval,
			EnableProfiling:             f.EnableProfiling,
			ExtraArgs:                   f.ExtraArgs,
		},
		MaxTransactionAge:  f.MaxTransactionAge,
		Runtimes:           f.Runtimes,
		RuntimeProvisioner: f.RuntimeProvisioner,
		RuntimeConfig:      f.RuntimeConfig,
	})
}

// ByzantineFixture is a byzantine node fixture.
type ByzantineFixture struct { // nolint: maligned
	NodeFixture

	Script    string     `json:"script"`
	ExtraArgs []Argument `json:"extra_args"`

	IdentitySeed string `json:"identity_seed"`
	Entity       int    `json:"entity"`

	EnableProfiling bool `json:"enable_profiling"`

	ActivationEpoch beacon.EpochTime `json:"activation_epoch"`
	Runtime         int              `json:"runtime"`

	// Consensus contains configuration for the consensus backend.
	Consensus ConsensusFixture `json:"consensus"`

	EnableDefaultLogWatcherHandlerFactories bool                        `json:"enable_default_log_fac"`
	LogWatcherHandlerFactories              []log.WatcherHandlerFactory `json:"-"`
}

// Create instantiates the byzantine node described by the fixture.
func (f *ByzantineFixture) Create(net *Network) (*Byzantine, error) {
	entity, err := resolveEntity(net, f.Entity)
	if err != nil {
		return nil, err
	}

	return net.NewByzantine(&ByzantineCfg{
		NodeCfg: NodeCfg{
			Name:                                     f.Name,
			DisableDefaultLogWatcherHandlerFactories: !f.EnableDefaultLogWatcherHandlerFactories,
			LogWatcherHandlerFactories:               f.LogWatcherHandlerFactories,
			Consensus:                                f.Consensus,
			EnableProfiling:                          f.EnableProfiling,
			AllowEarlyTermination:                    true,
			Entity:                                   entity,
		},
		Script:          f.Script,
		ExtraArgs:       f.ExtraArgs,
		IdentitySeed:    f.IdentitySeed,
		ActivationEpoch: f.ActivationEpoch,
		Runtime:         f.Runtime,
	})
}

func resolveEntity(net *Network, index int) (*Entity, error) {
	entities := net.Entities()
	if index < 0 || index >= len(entities) {
		return nil, fmt.Errorf("invalid entity index: %d", index)
	}
	return entities[index], nil
}

func resolveValidators(net *Network, indices []int) ([]*Validator, error) {
	allValidators := net.Validators()
	var validators []*Validator
	for _, index := range indices {
		if index < 0 || index >= len(allValidators) {
			return nil, fmt.Errorf("invalid validator index: %d", index)
		}
		validators = append(validators, allValidators[index])
	}
	return validators, nil
}

func resolveStorageWorkers(net *Network, indices []int) ([]*Storage, error) {
	allStorageWorkers := net.StorageWorkers()
	var storageWorkers []*Storage
	for _, index := range indices {
		if index < 0 || index >= len(allStorageWorkers) {
			return nil, fmt.Errorf("invalid storage index: %d", index)
		}
		storageWorkers = append(storageWorkers, allStorageWorkers[index])
	}
	return storageWorkers, nil
}

func resolveKeymanagerWorkers(net *Network, indices []int) ([]*Keymanager, error) {
	allKeymanagerWorkers := net.Keymanagers()
	var keymanagerWorkers []*Keymanager
	for _, index := range indices {
		if index < 0 || index >= len(allKeymanagerWorkers) {
			return nil, fmt.Errorf("invalid keymanager index: %d", index)
		}
		keymanagerWorkers = append(keymanagerWorkers, allKeymanagerWorkers[index])
	}
	return keymanagerWorkers, nil
}

func resolveRuntime(net *Network, index int) (*Runtime, error) {
	runtimes := net.Runtimes()
	if index < 0 || index >= len(runtimes) {
		return nil, fmt.Errorf("invalid runtime index: %d", index)
	}
	return runtimes[index], nil
}

func resolveRuntimeOfKind(net *Network, index int, kind registry.RuntimeKind) (*Runtime, error) {
	runtime, err := resolveRuntime(net, index)
	if err != nil {
		return nil, err
	}
	if runtime.kind != kind {
		return nil, fmt.Errorf("runtime %d has an incorrect kind (expected: %s got: %s)",
			index,
			kind,
			runtime.kind,
		)
	}
	return runtime, nil
}

func resolveSentries(net *Network, indices []int) ([]*Sentry, error) {
	allSentries := net.Sentries()
	var sentries []*Sentry
	for _, index := range indices {
		if index < 0 || index >= len(allSentries) {
			return nil, fmt.Errorf("invalid sentry index: %d", index)
		}
		sentries = append(sentries, allSentries[index])
	}
	return sentries, nil
}

func resolveKMPolicy(net *Network, index int) (*KeymanagerPolicy, error) {
	policies := net.keymanagerPolicies
	if index < 0 || index >= len(policies) {
		return nil, fmt.Errorf("invalid policy index: %d", index)
	}
	return policies[index], nil
}
