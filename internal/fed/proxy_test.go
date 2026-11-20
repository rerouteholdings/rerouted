package fed

import (
	"net/http"
	"reflect"
	"testing"
)

// Federation requests honor HTTPS_PROXY, HTTP_PROXY, and NO_PROXY.
func TestTransportUsesEnvironmentProxy(t *testing.T) {
	tr := newTransport()
	if tr.Proxy == nil || reflect.ValueOf(tr.Proxy).Pointer() != reflect.ValueOf(http.ProxyFromEnvironment).Pointer() {
		t.Fatal("the federation transport doesn't use http.ProxyFromEnvironment")
	}
}
