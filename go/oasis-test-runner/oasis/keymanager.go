package oasis

import (
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	kmCmd "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/keymanager"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
)

const (
	kmStatusFile = "keymanager_status.json"
	kmPolicyFile = "keymanager_policy.cbor"

	keymanagerIdentitySeedTemplate = "ekiden node keymanager %d"
)

// KeymanagerPolicy is an Oasis key manager policy document.
type KeymanagerPolicy struct {
	net *Network
	dir *env.Dir

	statusArgs []string

	runtime *Runtime
	serial  int
}

// KeymanagerPolicyCfg is an Oasis key manager policy document configuration.
type KeymanagerPolicyCfg struct {
	Runtime *Runtime
	Serial  int
}

func (pol *KeymanagerPolicy) provisionStatusArgs() []string {
	return pol.statusArgs
}

func (pol *KeymanagerPolicy) provision() error {
	if pol.runtime.teeHardware == node.TEEHardwareInvalid {
		// No policy document.
		pol.statusArgs = append(pol.statusArgs, "--"+kmCmd.CfgPolicyFile, "")
	} else {
		// Policy signed with test keys.
		policyPath := filepath.Join(pol.dir.String(), kmPolicyFile)
		policyArgs := []string{
			"keymanager", "init_policy",
			"--" + flags.CfgDebugDontBlameOasis,
			"--" + kmCmd.CfgPolicyFile, policyPath,
			"--" + kmCmd.CfgPolicyID, pol.runtime.id.String(),
			"--" + kmCmd.CfgPolicySerial, strconv.Itoa(pol.serial),
		}
		for _, mrEnclave := range pol.runtime.mrEnclaves {
			policyArgs = append(policyArgs, []string{
				"--" + kmCmd.CfgPolicyEnclaveID, mrEnclave.String() + pol.runtime.mrSigner.String(),
			}...)
		}

		for _, rt := range pol.net.runtimes {
			if rt.teeHardware == node.TEEHardwareInvalid || rt.kind != registry.KindCompute {
				continue
			}

			for _, mrEnclave := range rt.mrEnclaves {
				arg := fmt.Sprintf("%s=%s%s", rt.id, mrEnclave, rt.mrSigner)
				policyArgs = append(policyArgs, "--"+kmCmd.CfgPolicyMayQuery, arg)
			}
		}

		w, err := pol.dir.NewLogWriter("provision-policy.log")
		if err != nil {
			return err
		}
		defer w.Close()

		if err = pol.net.runNodeBinary(w, policyArgs...); err != nil {
			pol.net.logger.Error("failed to provision keymanager policy",
				"err", err,
			)
			return fmt.Errorf("oasis/keymanager: failed to provision keymanager policy: %w", err)
		}

		// Sign policy with test keys.
		signArgsTpl := []string{
			"keymanager", "sign_policy",
			"--" + common.CfgDebugAllowTestKeys,
			"--" + flags.CfgDebugDontBlameOasis,
			"--" + kmCmd.CfgPolicyFile, policyPath,
		}
		for i := 1; i <= 3; i++ {
			signatureFile := filepath.Join(pol.dir.String(), fmt.Sprintf("%s.sign.%d", kmPolicyFile, i))
			signArgs := append([]string{}, signArgsTpl...)
			signArgs = append(signArgs, []string{
				"--" + kmCmd.CfgPolicySigFile, signatureFile,
				"--" + kmCmd.CfgPolicyTestKey, fmt.Sprintf("%d", i),
			}...)
			pol.statusArgs = append(pol.statusArgs, "--"+kmCmd.CfgPolicySigFile, signatureFile)

			w, err := pol.dir.NewLogWriter("provision-policy-sign.log")
			if err != nil {
				return err
			}
			defer w.Close()

			if err = pol.net.runNodeBinary(w, signArgs...); err != nil {
				pol.net.logger.Error("failed to sign keymanager policy",
					"err", err,
				)
				return fmt.Errorf("oasis/keymanager: failed to sign keymanager policy: %w", err)
			}
		}

		pol.statusArgs = append(pol.statusArgs, "--"+kmCmd.CfgPolicyFile, policyPath)
	}

	return nil
}

// NewKeymanagerPolicy provisions a new keymanager policy and adds it to the
// network.
func (net *Network) NewKeymanagerPolicy(cfg *KeymanagerPolicyCfg) (*KeymanagerPolicy, error) {
	policyName := fmt.Sprintf("keymanager-policy-%d", cfg.Serial)

	policyDir, err := net.baseDir.NewSubDir(policyName)
	if err != nil {
		net.logger.Error("failed to create keymanager policy subdir",
			"err", err,
		)
		return nil, fmt.Errorf("oasis/keymanager: failed to create keymanager policy subdir: %w", err)
	}

	newPol := &KeymanagerPolicy{
		net:     net,
		dir:     policyDir,
		runtime: cfg.Runtime,
		serial:  cfg.Serial,
	}
	net.keymanagerPolicies = append(net.keymanagerPolicies, newPol)

	return newPol, nil
}

// Keymanager is an Oasis key manager.
type Keymanager struct { // nolint: maligned
	*Node

	sentryIndices []int

	runtime            *Runtime
	policy             *KeymanagerPolicy
	runtimeProvisioner string

	sentryPubKey     signature.PublicKey
	tmAddress        string
	consensusPort    uint16
	workerClientPort uint16

	mayGenerate bool
}

// KeymanagerCfg is the Oasis key manager provisioning configuration.
type KeymanagerCfg struct {
	NodeCfg

	SentryIndices []int

	Runtime            *Runtime
	Policy             *KeymanagerPolicy
	RuntimeProvisioner string
}

// IdentityKeyPath returns the paths to the node's identity key.
func (km *Keymanager) IdentityKeyPath() string {
	return nodeIdentityKeyPath(km.dir)
}

// P2PKeyPath returns the paths to the node's P2P key.
func (km *Keymanager) P2PKeyPath() string {
	return nodeP2PKeyPath(km.dir)
}

// ConsensusKeyPath returns the path to the node's consensus key.
func (km *Keymanager) ConsensusKeyPath() string {
	return nodeConsensusKeyPath(km.dir)
}

// TLSKeyPath returns the path to the node's TLS key.
func (km *Keymanager) TLSKeyPath() string {
	return nodeTLSKeyPath(km.dir)
}

// TLSCertPath returns the path to the node's TLS certificate.
func (km *Keymanager) TLSCertPath() string {
	return nodeTLSCertPath(km.dir)
}

// ExportsPath returns the path to the node's exports data dir.
func (km *Keymanager) ExportsPath() string {
	return nodeExportsPath(km.dir)
}

func (km *Keymanager) provisionGenesis() error {
	if km.runtime.excludeFromGenesis {
		return nil
	}

	// Provision status. We can only provision this here as we need
	// a list of runtimes allowed to query the key manager.
	statusArgs := []string{
		"keymanager", "init_status",
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + kmCmd.CfgStatusID, km.runtime.id.String(),
		"--" + kmCmd.CfgStatusFile, filepath.Join(km.dir.String(), kmStatusFile),
	}
	statusArgs = append(statusArgs, km.policy.provisionStatusArgs()...)

	w, err := km.dir.NewLogWriter("provision-status.log")
	if err != nil {
		return err
	}
	defer w.Close()

	if err = km.net.runNodeBinary(w, statusArgs...); err != nil {
		km.net.logger.Error("failed to provision keymanager status",
			"err", err,
		)
		return fmt.Errorf("oasis/keymanager: failed to provision keymanager status: %w", err)
	}

	return nil
}

func (km *Keymanager) toGenesisArgs() []string {
	if km.runtime.excludeFromGenesis {
		return nil
	}

	return []string{
		"--keymanager", filepath.Join(km.dir.String(), kmStatusFile),
	}
}

func (km *Keymanager) AddArgs(args *argBuilder) error {
	sentries, err := resolveSentries(km.net, km.sentryIndices)
	if err != nil {
		return err
	}

	runtimeBinaries := km.runtime.binaries[km.runtime.teeHardware]
	if len(runtimeBinaries) < 1 {
		return fmt.Errorf("oasis/keymanager: no runtime binaries configured")
	}

	args.debugDontBlameOasis().
		debugAllowTestKeys().
		debugEnableProfiling(km.Node.pprofPort).
		workerCertificateRotation(true).
		tendermintCoreAddress(km.consensusPort).
		tendermintSubmissionGasPrice(km.consensus.SubmissionGasPrice).
		tendermintPrune(km.consensus.PruneNumKept).
		tendermintRecoverCorruptedWAL(km.consensus.TendermintRecoverCorruptedWAL).
		workerClientPort(km.workerClientPort).
		runtimeProvisioner(km.runtimeProvisioner).
		runtimeSGXLoader(km.net.cfg.RuntimeSGXLoaderBinary).
		// XXX: could support configurable binary idx if ever needed.
		runtimePath(km.runtime.id, runtimeBinaries[0]).
		workerKeymanagerEnabled().
		workerKeymanagerRuntimeID(km.runtime.id).
		configureDebugCrashPoints(km.crashPointsProbability).
		tendermintSupplementarySanity(km.supplementarySanityInterval).
		appendNetwork(km.net).
		appendEntity(km.entity)

	if km.mayGenerate {
		args.workerKeymanagerMayGenerate()
	}

	// Sentry configuration.
	if len(sentries) > 0 {
		args.addSentries(sentries).
			tendermintDisablePeerExchange()
	} else {
		args.appendSeedNodes(km.net.seeds)
	}

	return nil
}

// NewKeymanager provisions a new keymanager and adds it to the network.
func (net *Network) NewKeymanager(cfg *KeymanagerCfg) (*Keymanager, error) {
	kmName := fmt.Sprintf("keymanager-%d", len(net.keymanagers))
	host, err := net.GetNamedNode(kmName, &cfg.NodeCfg)
	if err != nil {
		return nil, err
	}

	if cfg.Policy == nil {
		return nil, fmt.Errorf("oasis/keymanager: missing policy")
	}

	// Pre-provision the node identity so that we can update the entity.
	err = host.setProvisionedIdentity(false, fmt.Sprintf(keymanagerIdentitySeedTemplate, len(net.keymanagers)))
	if err != nil {
		return nil, fmt.Errorf("oasis/keymanager: failed to provision node identity: %w", err)
	}
	// Sentry client cert.
	pk, ok := host.sentryCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("oasis/keymanager: bad sentry client public key type (expected: Ed25519 got: %T)", host.sentryCert.PublicKey)
	}
	var sentryPubKey signature.PublicKey
	if err := sentryPubKey.UnmarshalBinary(pk[:]); err != nil {
		return nil, fmt.Errorf("oasis/keymanager: sentry client public key unmarshal failure: %w", err)
	}

	if cfg.RuntimeProvisioner == "" {
		cfg.RuntimeProvisioner = runtimeRegistry.RuntimeProvisionerSandboxed
	}

	km := &Keymanager{
		Node:               host,
		runtime:            cfg.Runtime,
		policy:             cfg.Policy,
		runtimeProvisioner: cfg.RuntimeProvisioner,
		sentryIndices:      cfg.SentryIndices,
		tmAddress:          crypto.PublicKeyToTendermint(&host.p2pSigner).Address().String(),
		sentryPubKey:       sentryPubKey,
		consensusPort:      host.getProvisionedPort(nodePortConsensus),
		workerClientPort:   host.getProvisionedPort(nodePortClient),
		mayGenerate:        len(net.keymanagers) == 0,
	}

	net.keymanagers = append(net.keymanagers, km)
	host.features = append(host.features, km)

	return km, nil
}
