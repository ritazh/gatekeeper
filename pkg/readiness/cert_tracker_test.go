/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package readiness_test

import (
 	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onsi/gomega"
    "github.com/open-policy-agent/cert-controller/pkg/rotator"
	"github.com/open-policy-agent/gatekeeper/pkg/readiness"
)

const (
	certName       = "tls.crt"
	keyName        = "tls.key"
	caCertName     = "ca.crt"
	caName         = "ca"
	caOrganization = "org"
	certDir        = ""
	dnsName        = "service.namespace"
)

var (
	cr = &rotator.CertRotator{
		CAName:         "ca",
		CAOrganization: "org",
		DNSName:        "service.namespace",
	}
)

// Test_CertTracker periodically verifies the webhook tls cert is valid,
// the generated cert is valid before it's expired
// the readiness probe returns nil if valid, otherwise returns an error.
func Test_CertTracker(t *testing.T) {
	g := gomega.NewWithT(t)

	mgr, _ := setupManager(t)

	now := time.Now()
	begin := now.Add(-1 * time.Hour)
	end := now.Add(3 * time.Second)

	caArtifacts, err := cr.CreateCACert(begin, end)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "creating ca cert")

	cert, key, err := cr.CreateCertPEM(caArtifacts, begin, end)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "creating cert pem")

	caCrtFile := filepath.Join(certDir, caCertName)
	defer os.Remove(caCrtFile)
	if err != nil {
		t.Fatalf("expected error to be nil, got: %+v", err)
	}
	err = ioutil.WriteFile(caCrtFile, caArtifacts.CertPEM, 0644)
	if err != nil {
		t.Fatalf("expected error to be nil, got: %+v", err)
	}

	crtFile := filepath.Join(certDir, certName)
	defer os.Remove(crtFile)
	if err != nil {
		t.Fatalf("expected error to be nil, got: %+v", err)
	}
	err = ioutil.WriteFile(crtFile, cert, 0644)
	if err != nil {
		t.Fatalf("expected error to be nil, got: %+v", err)
	}

	keyFile := filepath.Join(certDir, keyName)
	defer os.Remove(keyFile)
	if err != nil {
		t.Fatalf("expected error to be nil, got: %+v", err)
	}
	err = ioutil.WriteFile(keyFile, key, 0644)
	if err != nil {
		t.Fatalf("expected error to be nil, got: %+v", err)
	}

	err = readiness.SetupCertTracker(mgr, certDir, dnsName)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "setting up cert tracker")
	stopMgr, mgrStopped := StartTestManager(mgr, g)
	defer func() {
		close(stopMgr)
		mgrStopped.Wait()
	}()

	g.Eventually(func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return probeIsReady(ctx)
	}, 5*time.Second, 1*time.Second).Should(gomega.BeFalse())
}

// Test_CertTracker_NoFile verifies the webhook tls cert is valid,
// the readiness probe returns returns an error if there's no file.
func Test_CertTracker_NoFile(t *testing.T) {
	g := gomega.NewWithT(t)

	mgr, _ := setupManager(t)
	err := readiness.SetupCertTracker(mgr, "", "")
	g.Expect(err).NotTo(gomega.HaveOccurred(), "setting up cert tracker")

	stopMgr, mgrStopped := StartTestManager(mgr, g)
	defer func() {
		close(stopMgr)
		mgrStopped.Wait()
	}()

	g.Eventually(func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return probeIsReady(ctx)
	}, 3*time.Second, 1*time.Second).Should(gomega.BeFalse())
}
