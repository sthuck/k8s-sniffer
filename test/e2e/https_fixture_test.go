//go:build e2e

package e2e_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	nginxImage     = "nginx:1.27-bookworm"
	httpsName      = "https-openssl"
	httpsMarker    = "e2e-secret-token"
	httpsNamespace = "e2e-fixtures"
)

func (e *e2eEnv) ensureHTTPSOpenSSL() {
	e.t.Helper()
	ctx := context.Background()
	certPEM, keyPEM, err := selfSignedCert([]string{
		httpsName,
		httpsName + "." + httpsNamespace,
		httpsName + "." + httpsNamespace + ".svc",
		httpsName + "." + httpsNamespace + ".svc.cluster.local",
		"localhost",
		"127.0.0.1",
	})
	if err != nil {
		e.t.Fatalf("generate cert: %v", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: httpsName + "-tls", Namespace: httpsNamespace},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}
	if _, err := e.client.CoreV1().Secrets(httpsNamespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		e.t.Fatalf("create tls secret: %v", err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: httpsName + "-nginx", Namespace: httpsNamespace},
		Data: map[string]string{
			"https.conf": fmt.Sprintf(`server {
    listen 443 ssl;
    ssl_certificate     /etc/nginx/certs/tls.crt;
    ssl_certificate_key /etc/nginx/certs/tls.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    location / {
        default_type text/plain;
        return 200 "%s\n";
    }
    location /%s {
        default_type text/plain;
        return 200 "%s\n";
    }
}
`, httpsMarker, httpsMarker, httpsMarker),
		},
	}
	if _, err := e.client.CoreV1().ConfigMaps(httpsNamespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		e.t.Fatalf("create nginx configmap: %v", err)
	}

	labels := map[string]string{"app": httpsName}
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: httpsName, Namespace: httpsNamespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "nginx",
						Image: nginxImage,
						Ports: []corev1.ContainerPort{{ContainerPort: 443}},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "certs", MountPath: "/etc/nginx/certs", ReadOnly: true},
							{Name: "conf", MountPath: "/etc/nginx/conf.d", ReadOnly: true},
						},
					}},
					Volumes: []corev1.Volume{
						{Name: "certs", VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{SecretName: httpsName + "-tls"},
						}},
						{Name: "conf", VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: httpsName + "-nginx"}},
						}},
					},
				},
			},
		},
	}
	if _, err := e.client.AppsV1().Deployments(httpsNamespace).Create(ctx, dep, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		e.t.Fatalf("create https deployment: %v", err)
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: httpsName, Namespace: httpsNamespace},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports:    []corev1.ServicePort{{Port: 443, TargetPort: intstr.FromInt(443)}},
		},
	}
	if _, err := e.client.CoreV1().Services(httpsNamespace).Create(ctx, svc, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		e.t.Fatalf("create https service: %v", err)
	}

	waitForDeployments(e.t, e.client, httpsNamespace, httpsName)
}

func (e *e2eEnv) httpsGETInCluster(path string) {
	e.t.Helper()
	if path == "" {
		path = "/" + httpsMarker
	}
	url := fmt.Sprintf("https://%s.%s.svc.cluster.local%s", httpsName, httpsNamespace, path)
	cmd := exec.CommandContext(context.Background(), "kubectl",
		"--context", e.kubeContext,
		"-n", httpsNamespace,
		"run", fmt.Sprintf("curl-https-%d", time.Now().UnixNano()),
		"--rm", "-i", "--restart=Never",
		"--image="+curlImage,
		"--", "curl", "-kfsS", url,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.t.Fatalf("https GET %s: %v (%s)", url, err, out)
	}
}

func (e *e2eEnv) startPortForward(service string, remotePort int) (localPort int, stop func()) {
	e.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatalf("listen: %v", err)
	}
	localPort = ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "kubectl",
		"--context", e.kubeContext,
		"-n", httpsNamespace,
		"port-forward", "svc/"+service, fmt.Sprintf("%d:%d", localPort, remotePort),
	)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		e.t.Fatalf("port-forward: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return localPort, func() {
				cancel()
				_ = cmd.Wait()
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	_ = cmd.Wait()
	e.t.Fatal("timed out waiting for port-forward")
	return 0, nil
}

func httpsGETWithKeylog(url, keylogPath string) error {
	f, err := os.OpenFile(keylogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				KeyLogWriter:       f,
			},
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}
	return nil
}

func selfSignedCert(hosts []string) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"k8s-sniffer-e2e"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     nil,
		IPAddresses:  nil,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}
