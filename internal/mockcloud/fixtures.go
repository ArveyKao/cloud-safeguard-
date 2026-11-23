package mockcloud

import (
	"sync"
)

// Mock fixture identities (docs/CONTRACT.md §8.3). They are part of the demo
// contract: scenarios reference these exact instance and domain names.
const (
	// MockAccountID is the synthetic Alibaba Cloud account id carried by mock
	// tokens and used in resource ARNs.
	MockAccountID = "1234567890123456"

	zoneArveykao    = "arveykao.com"
	zoneGuanlan     = "guanlanstudio.com"
	zoneIDArveykao  = "dns-demo-arveykao"
	zoneIDGuanlan   = "dns-demo-guanlan"
	recordStatusUp  = "ENABLE"
	instanceRunning = "running"
	instanceStopped = "stopped"
	ecsService      = "ecs"
	dnsService      = "alidns"
	ramService      = "ram"
)

// ecsInstance is one in-memory ECS fixture instance. RegionId is filled from
// the presenting token when a response is rendered.
type ecsInstance struct {
	InstanceID   string `json:"InstanceId"`
	InstanceName string `json:"InstanceName"`
	Status       string `json:"Status"`
	RegionID     string `json:"RegionId"`
}

// dnsZone is one in-memory DNS fixture zone.
type dnsZone struct {
	DomainName string `json:"DomainName"`
	DomainID   string `json:"DomainId"`
}

// dnsRecord is one in-memory DNS record.
type dnsRecord struct {
	RecordID string `json:"RecordId"`
	RR       string `json:"RR"`
	Type     string `json:"Type"`
	Value    string `json:"Value"`
	TTL      int    `json:"TTL"`
	Status   string `json:"Status"`
}

// ramUser is one in-memory RAM (identity) fixture user. RAM exists in the mock
// cloud only so the IAM prohibition can be demonstrated end to end: every
// credential the control plane mints carries a deny for ram:*, so this route
// must always answer 403 Forbidden.RAM.
type ramUser struct {
	UserID      string `json:"UserId"`
	UserName    string `json:"UserName"`
	DisplayName string `json:"DisplayName"`
}

// cloudState is the mutable, per-handler fixture state. It resets whenever the
// process (or handler) is recreated.
type cloudState struct {
	mu            sync.Mutex
	instances     map[string]*ecsInstance
	instanceOrder []string
	zones         map[string]*dnsZone
	zoneOrder     []string
	records       map[string][]*dnsRecord
	nextRecordSeq int
	ramUsers      []ramUser
}

// newCloudState builds the frozen fixtures.
func newCloudState() *cloudState {
	st := &cloudState{
		instances:     make(map[string]*ecsInstance),
		zones:         make(map[string]*dnsZone),
		records:       make(map[string][]*dnsRecord),
		nextRecordSeq: 4,
	}
	for _, inst := range []*ecsInstance{
		{InstanceID: "i-2ze0demo001", InstanceName: "web-01", Status: instanceRunning},
		{InstanceID: "i-2ze0demo002", InstanceName: "worker-01", Status: instanceStopped},
		{InstanceID: "i-2ze0demo003", InstanceName: "db-01", Status: instanceRunning},
	} {
		st.instances[inst.InstanceID] = inst
		st.instanceOrder = append(st.instanceOrder, inst.InstanceID)
	}

	for _, z := range []*dnsZone{
		{DomainName: zoneArveykao, DomainID: zoneIDArveykao},
		{DomainName: zoneGuanlan, DomainID: zoneIDGuanlan},
	} {
		st.zones[z.DomainName] = z
		st.zoneOrder = append(st.zoneOrder, z.DomainName)
	}
	st.records[zoneArveykao] = []*dnsRecord{
		{RecordID: "dns-rec-0001", RR: "@", Type: "A", Value: "8.153.177.205", TTL: 600, Status: recordStatusUp},
		{RecordID: "dns-rec-0002", RR: "www", Type: "A", Value: "8.153.177.205", TTL: 600, Status: recordStatusUp},
		{RecordID: "dns-rec-0003", RR: "_acme-challenge", Type: "TXT", Value: "demo-token-123", TTL: 600, Status: recordStatusUp},
	}
	st.records[zoneGuanlan] = nil
	st.ramUsers = []ramUser{
		{UserID: "ram-demo-0001", UserName: "ops-admin", DisplayName: "Operations admin"},
		{UserID: "ram-demo-0002", UserName: "csg-broker", DisplayName: "Cloud Safeguard broker"},
	}
	return st
}

// listRAMUsers returns a copy of the RAM fixture users in stable order.
func (st *cloudState) listRAMUsers() []ramUser {
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]ramUser(nil), st.ramUsers...)
}

// listInstances returns a copy of the ECS fixture list in stable order.
func (st *cloudState) listInstances() []ecsInstance {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]ecsInstance, 0, len(st.instanceOrder))
	for _, id := range st.instanceOrder {
		out = append(out, *st.instances[id])
	}
	return out
}

// getInstance returns a copy of one fixture instance.
func (st *cloudState) getInstance(id string) (ecsInstance, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	inst, ok := st.instances[id]
	if !ok {
		return ecsInstance{}, false
	}
	return *inst, true
}

// setInstanceStatus mutates one fixture instance's status.
func (st *cloudState) setInstanceStatus(id, status string) (ecsInstance, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	inst, ok := st.instances[id]
	if !ok {
		return ecsInstance{}, false
	}
	inst.Status = status
	return *inst, true
}

// listZones returns a copy of the DNS zones in stable order.
func (st *cloudState) listZones() []dnsZone {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]dnsZone, 0, len(st.zoneOrder))
	for _, name := range st.zoneOrder {
		out = append(out, *st.zones[name])
	}
	return out
}

// hasZone reports whether the zone exists.
func (st *cloudState) hasZone(zone string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	_, ok := st.zones[zone]
	return ok
}

// listRecords returns a copy of a zone's records.
func (st *cloudState) listRecords(zone string) ([]dnsRecord, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.zones[zone]; !ok {
		return nil, false
	}
	recs := st.records[zone]
	out := make([]dnsRecord, 0, len(recs))
	for _, r := range recs {
		out = append(out, *r)
	}
	return out, true
}

// addRecord creates a record in an existing zone.
func (st *cloudState) addRecord(zone string, rec dnsRecord) (dnsRecord, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.zones[zone]; !ok {
		return dnsRecord{}, false
	}
	rec.RecordID = "dns-rec-" + itoa4(st.nextRecordSeq)
	st.nextRecordSeq++
	rec.Status = recordStatusUp
	stored := rec
	st.records[zone] = append(st.records[zone], &stored)
	return rec, true
}

// deleteRecord removes a record from an existing zone.
func (st *cloudState) deleteRecord(zone, recordID string) (bool, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.zones[zone]; !ok {
		return false, false
	}
	recs := st.records[zone]
	for i, r := range recs {
		if r.RecordID == recordID {
			st.records[zone] = append(recs[:i:i], recs[i+1:]...)
			return true, true
		}
	}
	return false, true
}

// itoa4 renders n as a 4-digit zero-padded string without importing strconv in
// two places.
func itoa4(n int) string {
	if n < 0 {
		n = 0
	}
	digits := [4]byte{'0', '0', '0', '0'}
	for i := 3; i >= 0 && n > 0; i-- {
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[:])
}
