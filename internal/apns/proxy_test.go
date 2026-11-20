package apns

import (
	"net/http"
	"reflect"
	"testing"
)

// Pushes to Apple honor HTTPS_PROXY and NO_PROXY.
func TestTransportUsesEnvironmentProxy(t *testing.T) {
	c := New(nil, "", "", "")
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok || tr.Proxy == nil || reflect.ValueOf(tr.Proxy).Pointer() != reflect.ValueOf(http.ProxyFromEnvironment).Pointer() {
		t.Fatal("the APNs transport doesn't use http.ProxyFromEnvironment")
	}
}
