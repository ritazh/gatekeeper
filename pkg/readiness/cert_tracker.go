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

package readiness

import (
	"io/ioutil"
	"net/http"
	"path/filepath"
	"time"

    "github.com/open-policy-agent/cert-controller/pkg/rotator"
	"github.com/pkg/errors"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var ctLog = logf.Log.WithName("cert-tracker")

// CertTracker tracks readiness for certs of the webhook.
type CertTracker struct {
	certDir string
	dnsName string
}

// NewCertTracker creates a new CertTracker
func NewCertTracker(certDir string, dnsName string) *CertTracker {
	return &CertTracker{
		certDir: certDir,
		dnsName: dnsName,
	}
}

// CheckCert implements healthz.Checker to report readiness based on cert validity
// the readiness probe returns nil if valid, otherwise returns an error.
func (c *CertTracker) CheckCert(req *http.Request) error {
	ctLog.V(1).Info("readiness checker CheckCert started")

	// Load files
	caCrt, err := ioutil.ReadFile(filepath.Join(c.certDir, "ca.crt"))
	if err != nil {
		return errors.Wrap(err, "Unable to open CA cert")
	}

	tlsCrt, err := ioutil.ReadFile(filepath.Join(c.certDir, "tls.crt"))
	if err != nil {
		return errors.Wrap(err, "Unable to open tls crt")
	}
	tlsKey, err := ioutil.ReadFile(filepath.Join(c.certDir, "tls.key"))
	if err != nil {
		return errors.Wrap(err, "Unable to open tls key")
	}
	valid, err := rotator.ValidCert(caCrt, tlsCrt, tlsKey, c.dnsName, time.Now())
	if err != nil || !valid {
		return errors.Wrap(err, "readiness checker CheckCert certs not valid")
	}
	ctLog.V(1).Info("readiness checker CheckCert completed")
	return nil
}
