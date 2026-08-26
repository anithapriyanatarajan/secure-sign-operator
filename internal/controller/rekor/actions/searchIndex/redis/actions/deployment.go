package actions

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/securesign/operator/internal/action"
	appconfig "github.com/securesign/operator/internal/config"
	"github.com/securesign/operator/internal/constants"
	"github.com/securesign/operator/internal/controller/rekor/actions"
	"github.com/securesign/operator/internal/images"
	"github.com/securesign/operator/internal/labels"
	"github.com/securesign/operator/internal/state"
	cutils "github.com/securesign/operator/internal/utils"
	"github.com/securesign/operator/internal/utils/kubernetes"
	"github.com/securesign/operator/internal/utils/kubernetes/ensure"
	"github.com/securesign/operator/internal/utils/kubernetes/ensure/deployment"
	"github.com/securesign/operator/internal/utils/tls"
	v1 "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	rhtasv1 "github.com/securesign/operator/api/v1"
)

const (
	storageVolumeName = "storage"
	configVolumeMount = "/config"
	redisConfPath     = configVolumeMount + "/redis.conf"
)

func NewDeployAction() action.Action[*rhtasv1.Rekor] {
	return &deployAction{}
}

type deployAction struct {
	action.BaseAction
}

func (i deployAction) Name() string {
	return "deploy"
}

func (i deployAction) CanHandle(_ context.Context, instance *rhtasv1.Rekor) bool {
	return enabled(instance) && state.FromInstance(instance, constants.ReadyCondition) >= state.Creating
}

func (i deployAction) Handle(ctx context.Context, instance *rhtasv1.Rekor) *action.Result {
	var (
		err    error
		result controllerutil.OperationResult
	)
	labels := labels.For(actions.RedisComponentName, actions.RedisDeploymentName, instance.Name)
	caPath, err := tls.CAPath(ctx, i.Client, instance)
	if err != nil {
		return i.Error(ctx, fmt.Errorf("failed to get CA path: %w", err), instance)
	}

	if result, err = kubernetes.CreateOrUpdate(ctx, i.Client,
		&v1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      actions.RedisDeploymentName,
				Namespace: instance.Namespace,
			},
		},
		i.ensureRedisDeployment(instance, actions.RBACRedisName, labels),
		deployment.TrustedCA(instance.GetTrustedCA(), actions.RedisDeploymentName, actions.RedisDeploymentName),
		ensure.Optional(statusTLS(instance).CertRef != nil, i.ensureTLS(statusTLS(instance), caPath)),
		ensure.ControllerReference[*v1.Deployment](instance, i.Client),
		ensure.Labels[*v1.Deployment](slices.Collect(maps.Keys(labels)), labels),
		deployment.Proxy(),
		deployment.GODEBUG(instance.GetAnnotations()),
		deployment.PodSecurityContext(),
	); err != nil {
		return i.Error(ctx, fmt.Errorf("could not create %s deployment: %w", actions.RedisDeploymentName, err), instance,
			metav1.Condition{
				Type:    actions.RedisCondition,
				Status:  metav1.ConditionFalse,
				Reason:  state.Failure.String(),
				Message: err.Error(),
			},
		)
	}

	if result != controllerutil.OperationResultNone {
		meta.SetStatusCondition(&instance.Status.Conditions, metav1.Condition{
			Type:    actions.RedisCondition,
			Status:  metav1.ConditionFalse,
			Reason:  state.Creating.String(),
			Message: "Redis created",
		})
		return i.ReturnOnChange(i.PersistStatus)(ctx, instance)
	} else {
		return i.Continue()
	}

}

func (i deployAction) ensureRedisDeployment(instance *rhtasv1.Rekor, sa string, labels map[string]string) func(*v1.Deployment) error {
	return func(dp *v1.Deployment) error {

		spec := &dp.Spec
		spec.Replicas = cutils.Pointer[int32](1)
		spec.Selector = &metav1.LabelSelector{
			MatchLabels: labels,
		}

		template := &spec.Template
		template.Labels = labels
		template.Spec.ServiceAccountName = sa

		container := kubernetes.FindContainerByNameOrCreate(&template.Spec, actions.RedisDeploymentName)
		container.Image = images.Registry.Get(images.RekorRedis)

		if err := i.ensurePassword(instance, container); err != nil {
			return err
		}

		port := kubernetes.FindPortByNameOrCreate(container, "redis")
		port.Protocol = core.ProtocolTCP
		port.ContainerPort = actions.RedisDeploymentPort

		if container.ReadinessProbe == nil {
			container.ReadinessProbe = &core.Probe{}
		}
		if container.ReadinessProbe.Exec == nil {
			container.ReadinessProbe.Exec = &core.ExecAction{}
		}

		container.ReadinessProbe.Exec.Command = []string{
			"/bin/sh", //nolint:goconst
			"-c",
			"-i",
			"test $(redis-cli -h 127.0.0.1 -a $REDIS_PASSWORD ping) = 'PONG'", //nolint:goconst
		}
		container.ReadinessProbe.InitialDelaySeconds = 0
		container.ReadinessProbe.PeriodSeconds = 10
		container.ReadinessProbe.TimeoutSeconds = 1
		container.ReadinessProbe.FailureThreshold = 3

		if container.LivenessProbe == nil {
			container.LivenessProbe = &core.Probe{}
		}
		if container.LivenessProbe.Exec == nil {
			container.LivenessProbe.Exec = &core.ExecAction{}
		}
		container.LivenessProbe.Exec.Command = []string{
			"/bin/sh",
			"-c",
			"-i",
			"test $(redis-cli -h 127.0.0.1 -a $REDIS_PASSWORD ping) = 'PONG'",
		}
		container.LivenessProbe.InitialDelaySeconds = 0
		container.LivenessProbe.PeriodSeconds = 10
		container.LivenessProbe.TimeoutSeconds = 1
		container.LivenessProbe.FailureThreshold = 3

		if container.StartupProbe == nil {
			container.StartupProbe = &core.Probe{}
		}
		if container.StartupProbe.Exec == nil {
			container.StartupProbe.Exec = &core.ExecAction{}
		}
		container.StartupProbe.Exec.Command = []string{
			"/bin/sh",
			"-c",
			"-i",
			"test $(redis-cli -h 127.0.0.1 -a $REDIS_PASSWORD ping) = 'PONG'",
		}
		container.StartupProbe.PeriodSeconds = 5
		container.StartupProbe.TimeoutSeconds = 5
		container.StartupProbe.FailureThreshold = 12

		volumeMount := kubernetes.FindVolumeMountByNameOrCreate(container, storageVolumeName)
		volumeMount.MountPath = "/data"

		volume := kubernetes.FindVolumeByNameOrCreate(&template.Spec, storageVolumeName)
		if volume.EmptyDir == nil {
			volume.EmptyDir = &core.EmptyDirVolumeSource{}
		}

		return nil
	}
}

func (i deployAction) ensurePassword(instance *rhtasv1.Rekor, container *core.Container) error {
	if instance.Status.SearchIndex.DbPasswordRef == nil {
		return errors.New("search index db password not found")
	}

	passwordEnv := kubernetes.FindEnvByNameOrCreate(container, "REDIS_PASSWORD")
	if passwordEnv.ValueFrom == nil {
		passwordEnv.ValueFrom = &core.EnvVarSource{}
	}
	if passwordEnv.ValueFrom.SecretKeyRef == nil {
		passwordEnv.ValueFrom.SecretKeyRef = &core.SecretKeySelector{}
	}
	passwordEnv.ValueFrom.SecretKeyRef.Name = instance.Status.SearchIndex.DbPasswordRef.Name
	passwordEnv.ValueFrom.SecretKeyRef.Key = instance.Status.SearchIndex.DbPasswordRef.Key
	return nil
}

// redisTLSProtocols maps an OpenShift TLS profile minimum version to the equivalent
// Redis "tls-protocols" allow-list (the minimum version plus every higher version). It
// returns an empty string when no minimum is set, so the directive is omitted and Redis
// keeps its built-in default.
func redisTLSProtocols(min configv1.TLSProtocolVersion) string {
	switch min {
	case configv1.VersionTLS10:
		return "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"
	case configv1.VersionTLS11:
		return "TLSv1.1 TLSv1.2 TLSv1.3"
	case configv1.VersionTLS12:
		return "TLSv1.2 TLSv1.3"
	case configv1.VersionTLS13:
		return "TLSv1.3"
	default:
		return ""
	}
}

// redisTLSCiphers splits an OpenShift TLS profile cipher list into the two Redis
// directives that mirror it: tls-ciphers (TLS 1.2 and below, OpenSSL name format) and
// tls-ciphersuites (TLS 1.3, "TLS_"-prefixed names, which OpenSSL also accepts). The
// OpenShift standard profiles already store 1.2 ciphers in OpenSSL format and 1.3
// ciphers in TLS_ format, so the values are passed through verbatim, colon-joined.
//
// WARNING: cipher names are handed to Redis/OpenSSL without validation. Unlike the Go
// endpoints (via ostls), which silently drop cipher names Go does not recognize, Redis
// has no such filtering: a custom TLS profile naming a cipher the Redis image's OpenSSL
// build does not support will make Redis reject redis.conf and crash-loop. This is a
// deliberate, documented trade-off to achieve full cipher adherence for the standard
// profiles.
func redisTLSCiphers(ciphers []string) (tls12 string, tls13 string) {
	var suites12, suites13 []string
	for _, c := range ciphers {
		if strings.HasPrefix(c, "TLS_") {
			suites13 = append(suites13, c)
			continue
		}
		suites12 = append(suites12, c)
	}
	return strings.Join(suites12, ":"), strings.Join(suites13, ":")
}

func (i deployAction) ensureTLS(tlsConfig rhtasv1.TLS, caPath string) func(deployment *v1.Deployment) error {
	return func(dp *v1.Deployment) error {
		if err := deployment.TLS(tlsConfig, actions.RedisDeploymentName)(dp); err != nil {
			return err
		}

		dbConfig := []string{
			fmt.Sprintf("tls-port %d", actions.RedisDeploymentPort),
			// disable non-tls ports
			"port 0",
			fmt.Sprintf("tls-cert-file %s", tls.TLSCertPath),
			fmt.Sprintf("tls-key-file %s", tls.TLSKeyPath),
			fmt.Sprintf("tls-ca-cert-file %s", caPath),
			// disable client authentication
			"tls-auth-clients no",
		}

		// Enforce the cluster TLS minimum protocol version on the Redis listener so the
		// in-cluster search-index connection honors the OpenShift TLS security profile.
		if protocols := redisTLSProtocols(appconfig.ClusterTLSProfile.MinTLSVersion); protocols != "" {
			dbConfig = append(dbConfig, fmt.Sprintf("tls-protocols \"%s\"", protocols))
		}

		// Mirror the profile's cipher suites onto the Redis listener, matching what ostls
		// applies to the operator's Go endpoints. tls-ciphers covers TLS 1.2, tls-ciphersuites
		// covers TLS 1.3. See redisTLSCiphers for the crash-loop risk with custom profiles.
		tls12, tls13 := redisTLSCiphers(appconfig.ClusterTLSProfile.Ciphers)
		if tls12 != "" {
			dbConfig = append(dbConfig, fmt.Sprintf("tls-ciphers \"%s\"", tls12))
		}
		if tls13 != "" {
			dbConfig = append(dbConfig, fmt.Sprintf("tls-ciphersuites \"%s\"", tls13))
		}

		config := kubernetes.FindVolumeByNameOrCreate(&dp.Spec.Template.Spec, "config")
		if config.EmptyDir == nil {
			config.EmptyDir = &core.EmptyDirVolumeSource{}
		}

		init := kubernetes.FindInitContainerByNameOrCreate(&dp.Spec.Template.Spec, "enable-tls")
		init.Image = images.Registry.Get(images.RekorRedis)
		initVolumeName := kubernetes.FindVolumeMountByNameOrCreate(init, config.Name)
		initVolumeName.MountPath = configVolumeMount
		init.Command = []string{"/bin/bash", "-c"}
		init.Args = []string{
			fmt.Sprintf("cp $REDIS_CONF %s\n", redisConfPath),
		}
		for _, v := range dbConfig {
			init.Args[0] += fmt.Sprintf("echo \"%s\" >> %s\n", v, redisConfPath)
		}

		container := kubernetes.FindContainerByNameOrCreate(&dp.Spec.Template.Spec, actions.RedisDeploymentName)
		container.Image = images.Registry.Get(images.RekorRedis)
		containerVolumeName := kubernetes.FindVolumeMountByNameOrCreate(container, config.Name)
		containerVolumeName.MountPath = configVolumeMount

		configPathEnv := kubernetes.FindEnvByNameOrCreate(container, "REDIS_CONF")
		configPathEnv.Value = redisConfPath

		if container.ReadinessProbe == nil {
			container.ReadinessProbe = &core.Probe{}
		}
		if container.ReadinessProbe.Exec == nil {
			container.ReadinessProbe.Exec = &core.ExecAction{}
		}

		container.ReadinessProbe.Exec.Command = []string{
			"/bin/sh",
			"-c",
			"-i",
			fmt.Sprintf("test $(redis-cli --tls --cacert %s -h 127.0.0.1 -a $REDIS_PASSWORD ping) = 'PONG'", caPath),
		}

		if container.LivenessProbe == nil {
			container.LivenessProbe = &core.Probe{}
		}
		if container.LivenessProbe.Exec == nil {
			container.LivenessProbe.Exec = &core.ExecAction{}
		}

		container.LivenessProbe.Exec.Command = []string{
			"/bin/sh",
			"-c",
			"-i",
			fmt.Sprintf("test $(redis-cli --tls --cacert %s -h 127.0.0.1 -a $REDIS_PASSWORD ping) = 'PONG'", caPath),
		}

		if container.StartupProbe == nil {
			container.StartupProbe = &core.Probe{}
		}
		if container.StartupProbe.Exec == nil {
			container.StartupProbe.Exec = &core.ExecAction{}
		}
		container.StartupProbe.Exec.Command = []string{
			"/bin/sh",
			"-c",
			"-i",
			fmt.Sprintf("test $(redis-cli --tls --cacert %s -h 127.0.0.1 -a $REDIS_PASSWORD ping) = 'PONG'", caPath),
		}

		return nil
	}
}
