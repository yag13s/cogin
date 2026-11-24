package memstore_test

import (
	"testing"

	"github.com/yag13s/cogin/store/memstore"
	"github.com/yag13s/cogin/store/storetest"
)

func TestContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) storetest.Store { return memstore.New() })
}
