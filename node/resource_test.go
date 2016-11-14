package node

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/lodastack/registry/model"
)

func TestSetResourceByID(t *testing.T) {
	s := mustNewStore(t)
	defer os.RemoveAll(s.Path())

	resourceByte, _ := json.Marshal(resMap1)

	if err := s.Open(true); err != nil {
		t.Fatalf("failed to open single-node store: %s", err.Error())
	}
	defer s.Close(true)
	s.WaitForLeader(10 * time.Second)
	tree, err := NewTree(s)

	// Set resource to leaf.
	leafID, err := tree.NewNode("test", rootID, Leaf)
	if err != nil {
		t.Fatalf("create leaf behind root fail: %s", err.Error())
	}
	err = tree.SetResourceByNodeID(leafID, "machine", resourceByte)
	if err != nil {
		t.Fatalf("set resource fail: %s, not match with expect\n", err.Error())
	}
	if res, err := tree.GetResourceByNodeID(leafID, "machine"); err != nil || len(*res) != 2 {
		t.Fatalf("get resource fail after set: %s\n", err.Error())
	} else {
		if (*res)[0]["host"] != "127.0.0.1" || (*res)[1]["host"] != "127.0.0.2" {
			t.Fatalf("resource not match with expect: %+v\n", *res)
		}
	}

	// Set resource to nonLeaf.
	nonLeafID, err := tree.NewNode("testNonLeaf", rootID, NonLeaf)
	if err != nil {
		t.Fatalf("create nonLeaf behind root fail: %s", err.Error())
	}
	if err = tree.SetResourceByNodeID(nonLeafID, "machine", resourceByte); err == nil {
		t.Fatalf("set resource fail: %s, not match with expect\n", err.Error())
	}
}

func TestSetResourceByNs(t *testing.T) {
	s := mustNewStore(t)
	defer os.RemoveAll(s.Path())

	resourceByte, _ := json.Marshal(resMap1)

	if err := s.Open(true); err != nil {
		t.Fatalf("failed to open single-node store: %s", err.Error())
	}
	defer s.Close(true)
	s.WaitForLeader(10 * time.Second)
	tree, err := NewTree(s)

	// Set resource to leaf.
	if _, err := tree.NewNode("test", rootID, Leaf); err != nil {
		t.Fatalf("create leaf behind root fail: %s", err.Error())
	}
	err = tree.SetResourceByNs("test."+rootNode, "machine", resourceByte)
	if err != nil {
		t.Fatalf("set resource fail: %s, not match with expect\n", err.Error())
	}
	if res, err := tree.GetResourceByNs("test."+rootNode, "machine"); err != nil || len(*res) != 2 {
		t.Fatalf("get resource fail after set: %s\n", err.Error())
	} else {
		if (*res)[0]["host"] != "127.0.0.1" || (*res)[1]["host"] != "127.0.0.2" {
			t.Fatalf("resource not match with expect: %+v\n", *res)
		}
	}

	// Set resource to nonLeaf.
	if _, err := tree.NewNode("testNonLeaf", rootID, NonLeaf); err != nil {
		t.Fatalf("create nonLeaf behind root fail: %s", err.Error())
	}
	if err = tree.SetResourceByNs("testNonLeaf."+rootNode, "machine", resourceByte); err == nil {
		t.Fatalf("set resource fail: %s, not match with expect\n", err.Error())
	}
}

func TestSearchResource(t *testing.T) {
	s := mustNewStore(t)
	defer os.RemoveAll(s.Path())

	resourceByte1, _ := json.Marshal(resMap1)
	resourceByte2, _ := json.Marshal(resMap2)

	if err := s.Open(true); err != nil {
		t.Fatalf("failed to open single-node store: %s", err.Error())
	}
	defer s.Close(true)
	s.WaitForLeader(10 * time.Second)
	tree, err := NewTree(s)

	// Set resource to leaf.
	if _, err := tree.NewNode("test1", rootID, Leaf); err != nil {
		t.Fatalf("create leaf behind root fail: %s", err.Error())
	}
	err = tree.SetResourceByNs("test1."+rootNode, "machine", resourceByte1)
	if err != nil {
		t.Fatalf("set resource fail: %s, not match with expect\n", err.Error())
	}
	if _, err := tree.NewNode("test2", rootID, Leaf); err != nil {
		t.Fatalf("create leaf behind root fail: %s", err.Error())
	}
	err = tree.SetResourceByNs("test2."+rootNode, "machine", resourceByte2)
	if err != nil {
		t.Fatalf("set resource fail: %s, not match with expect\n", err.Error())
	}

	// search 127.0.0.1 show get 1 node each has one resource.
	search1_1 := model.ResourceSearch{
		Key:   "host",
		Value: []byte("127.0.0.1"),
		Fuzzy: false,
	}
	search1_2 := search1_1
	search1_2.Fuzzy = true
	res, err := tree.SearchResourceByNs(rootNode, "machine", search1_1)
	if resMachine, ok := res["test1."+rootNode]; err != nil || len(res) != 1 || !ok {
		t.Fatalf("search host 127.0.0.1 by not fuzzy type not match with expect")
	} else {
		if ip, ok := (*resMachine)[0].ReadProperty("host"); !ok || ip != "127.0.0.1" {
			t.Fatalf("search host 127.0.0.1 by not fuzzy type not match with expect")
		}
	}
	res, err = tree.SearchResourceByNs(rootNode, "machine", search1_2)
	if resMachine, ok := res["test1."+rootNode]; err != nil || len(res) != 1 || !ok {
		t.Fatalf("search host 127.0.0.1 by fuzzy type not match with expect")
	} else {
		if ip, ok := (*resMachine)[0].ReadProperty("host"); !ok || ip != "127.0.0.1" {
			t.Fatalf("search host 127.0.0.1 by fuzzy type not match with expect")
		}
	}

	// search 127.0.0.2 show get 2 node each has one resource.
	search2_1 := model.ResourceSearch{
		Key:   "host",
		Value: []byte("127.0.0.2"),
		Fuzzy: false,
	}
	search2_2 := search2_1
	search2_2.Fuzzy = true
	if res, err = tree.SearchResourceByNs(rootNode, "machine", search2_1); err != nil || len(res) != 2 {
		t.Fatalf("search host 127.0.0.2 by not fuzzy type not match with expect")
	}
	if res, err = tree.SearchResourceByNs(rootNode, "machine", search2_2); err != nil || len(res) != 2 {
		t.Fatalf("search host 127.0.0.2 by fuzzy type not match with expect")
	}

	// search 127.0.0. with not fuzzy type should get none result.
	search3_1 := model.ResourceSearch{
		Key:   "host",
		Value: []byte("127.0.0."),
		Fuzzy: false,
	}
	// search 127.0.0. with fuzzy type should get two node, and each has two resource.
	search3_2 := search3_1
	search3_2.Fuzzy = true
	if res, err = tree.SearchResourceByNs(rootNode, "machine", search3_1); err != nil || len(res) != 0 {
		t.Fatalf("search host 127.0.0. by not fuzzy type not match with expect")
	}
	if res, err = tree.SearchResourceByNs(rootNode, "machine", search3_2); len(res) != 2 {
		t.Fatalf("search host 127.0.0. by fuzzy type not match with expect")
	}
	for _, resMachine := range res {
		if len(*resMachine) != 2 {
			t.Fatalf("search host 127.0.0.3 by fuzzy type not match with expect")
		}
	}
}

func TestGetResAfterSetOtherNs(t *testing.T) {
	s := mustNewStore(t)
	defer os.RemoveAll(s.Path())

	resourceByte1, _ := json.Marshal(resMap1)
	resourceByte2, _ := json.Marshal(resMap2)

	if err := s.Open(true); err != nil {
		t.Fatalf("failed to open single-node store: %s", err.Error())
	}
	defer s.Close(true)
	s.WaitForLeader(10 * time.Second)
	tree, err := NewTree(s)

	// Set resource to leaf.
	if _, err := tree.NewNode("leaf1", rootID, Leaf); err != nil {
		t.Fatalf("create leaf behind root fail: %s", err.Error())
	}
	err = tree.SetResourceByNs("leaf1."+rootNode, "machine", resourceByte1)
	if err != nil {
		t.Fatalf("set resource fail: %s, not match with expect\n", err.Error())
	}
	if res, err := tree.GetResourceByNs("leaf1."+rootNode, "machine"); err != nil || len(*res) != 2 {
		t.Fatalf("get resource fail after set: %s\n", err.Error())
	} else {
		if (*res)[0]["host"] != "127.0.0.1" || (*res)[1]["host"] != "127.0.0.2" {
			t.Fatalf("resource not match with expect: %+v\n", *res)
		}
	}

	// Set resource to leaf.
	if _, err := tree.NewNode("leaf2", rootID, Leaf); err != nil {
		t.Fatalf("create leaf behind root fail: %s", err.Error())
	}
	err = tree.SetResourceByNs("leaf2."+rootNode, "machine", resourceByte2)
	if err != nil {
		t.Fatalf("set resource fail: %s, not match with expect\n", err.Error())
	}
	if res, err := tree.GetResourceByNs("leaf2."+rootNode, "machine"); err != nil || len(*res) != 2 {
		t.Fatalf("get resource fail after set: %s\n", err.Error())
	} else {
		if (*res)[0]["host"] != "127.0.0.2" || (*res)[1]["host"] != "127.0.0.3" {
			t.Fatalf("resource not match with expect: %+v\n", *res)
		}
	}
}