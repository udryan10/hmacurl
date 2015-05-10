package signature

import (
	"testing"
)

func TestComputeHmac256(t *testing.T) {
	array := ComputeHmac256([]byte("secret"), "testMessage")
	// Expect the first array element to contain '52'
	if array[0] != 52 {
		t.Error("TestComputeHmac256 did not work as expected.")
	} else {
		t.Log("One test passed.")
	}
}
