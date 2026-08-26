package config

import (
	"time"

	configv1 "github.com/openshift/api/config/v1"
)

var (
	CreateTreeDeadline       int64 = 1200
	Openshift                bool
	OpenshiftAPIServerName   string
	APIServerTimeout         time.Duration
	IngressHostTemplate      = "%[1]s.local"
	DisableClusterTLSProfile bool

	// ClusterTLSProfile is the cluster-wide TLS security profile resolved at operator
	// startup (see resolveClusterTLSProfile in cmd/main.go). It always holds an effective
	// profile: the cluster profile on OpenShift, or the Intermediate defaults on vanilla
	// Kubernetes / when resolution is disabled. Component controllers read it to cascade the
	// profile to managed workloads (currently the Rekor search-index Redis config). It is set
	// once at startup and treated as read-only; the operator restarts to pick up changes.
	ClusterTLSProfile configv1.TLSProfileSpec
)
