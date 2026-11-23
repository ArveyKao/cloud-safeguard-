package mockcloud

import (
	"fmt"
	"net/http"
	"strings"
)

// ---- ECS handlers ----

// handleECSListInstances implements GET /v1/ecs/instances.
func handleECSListInstances(h *handler, r *http.Request, ac *authContext) (int, map[string]any, *cloudError) {
	region := ac.payload.Region
	instances := h.state.listInstances()
	for i := range instances {
		instances[i].RegionID = region
	}
	return http.StatusOK, map[string]any{
		"RegionId":  region,
		"Instances": instances,
	}, nil
}

// handleECSGetInstance implements GET /v1/ecs/instances/{id}.
func handleECSGetInstance(h *handler, r *http.Request, ac *authContext) (int, map[string]any, *cloudError) {
	id := r.PathValue("id")
	inst, ok := h.state.getInstance(id)
	if !ok {
		return 0, nil, errInstanceNotFound(id)
	}
	inst.RegionID = ac.payload.Region
	return http.StatusOK, map[string]any{"Instance": inst}, nil
}

// handleECSInstanceOp implements restart/start/stop on one instance.
func handleECSInstanceOp(h *handler, r *http.Request, ac *authContext, status string) (int, map[string]any, *cloudError) {
	id := r.PathValue("id")
	inst, ok := h.state.setInstanceStatus(id, status)
	if !ok {
		return 0, nil, errInstanceNotFound(id)
	}
	inst.RegionID = ac.payload.Region
	return http.StatusOK, map[string]any{"Instance": inst}, nil
}

// ---- DNS handlers ----

// handleDNSListZones implements GET /v1/dns/zones.
func handleDNSListZones(h *handler, _ *http.Request, _ *authContext) (int, map[string]any, *cloudError) {
	return http.StatusOK, map[string]any{"Domains": h.state.listZones()}, nil
}

// handleDNSListRecords implements GET /v1/dns/zones/{zone}/records.
func handleDNSListRecords(h *handler, r *http.Request, _ *authContext) (int, map[string]any, *cloudError) {
	zone := r.PathValue("zone")
	records, ok := h.state.listRecords(zone)
	if !ok {
		return 0, nil, errDomainNotFound(zone)
	}
	return http.StatusOK, map[string]any{
		"DomainRecords": map[string]any{"Record": records},
	}, nil
}

// dnsCreateRecordInput is the accepted record-create body.
type dnsCreateRecordInput struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

// handleDNSAddRecord implements POST /v1/dns/zones/{zone}/records.
func handleDNSAddRecord(h *handler, r *http.Request, _ *authContext) (int, map[string]any, *cloudError) {
	zone := r.PathValue("zone")
	if !h.state.hasZone(zone) {
		return 0, nil, errDomainNotFound(zone)
	}
	var input dnsCreateRecordInput
	if cerr := readJSONBody(r, &input); cerr != nil {
		return 0, nil, cerr
	}
	record, cerr := validateCreateRecord(input)
	if cerr != nil {
		return 0, nil, cerr
	}
	stored, ok := h.state.addRecord(zone, record)
	if !ok {
		return 0, nil, errDomainNotFound(zone)
	}
	return http.StatusOK, map[string]any{"Record": stored}, nil
}

// handleDNSDeleteRecord implements DELETE /v1/dns/zones/{zone}/records/{rid}.
func handleDNSDeleteRecord(h *handler, r *http.Request, _ *authContext) (int, map[string]any, *cloudError) {
	zone := r.PathValue("zone")
	recordID := r.PathValue("rid")
	found, zoneOK := h.state.deleteRecord(zone, recordID)
	if !zoneOK {
		return 0, nil, errDomainNotFound(zone)
	}
	if !found {
		return 0, nil, &cloudError{
			status:  http.StatusNotFound,
			code:    "InvalidDomainRecord.NotFound",
			message: fmt.Sprintf("The specified DNS record %q does not exist in zone %q", recordID, zone),
		}
	}
	return http.StatusOK, map[string]any{"RecordId": recordID}, nil
}

// validateCreateRecord normalizes and validates a record-create request.
func validateCreateRecord(in dnsCreateRecordInput) (dnsRecord, *cloudError) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return dnsRecord{}, &cloudError{http.StatusBadRequest, "InvalidParameter", "Record name (RR) is required"}
	}
	if len(name) > 128 {
		return dnsRecord{}, &cloudError{http.StatusBadRequest, "InvalidParameter", "Record name (RR) is too long"}
	}
	for _, r := range name {
		valid := r == '@' || r == '*' || r == '-' || r == '_' || r == '.' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !valid {
			return dnsRecord{}, &cloudError{http.StatusBadRequest, "InvalidParameter", "Record name (RR) contains invalid characters"}
		}
	}

	recordType := strings.ToUpper(strings.TrimSpace(in.Type))
	if !validRecordTypes[recordType] {
		return dnsRecord{}, &cloudError{
			http.StatusBadRequest,
			"InvalidParameter",
			"Record type must be one of A, AAAA, CNAME, TXT, MX",
		}
	}

	value := strings.TrimSpace(in.Value)
	if value == "" {
		return dnsRecord{}, &cloudError{http.StatusBadRequest, "InvalidParameter", "Record value is required"}
	}
	if len(value) > 4096 {
		return dnsRecord{}, &cloudError{http.StatusBadRequest, "InvalidParameter", "Record value is too long"}
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7F {
			return dnsRecord{}, &cloudError{http.StatusBadRequest, "InvalidParameter", "Record value contains control characters"}
		}
	}

	ttl := in.TTL
	if ttl == 0 {
		ttl = 600
	}
	if ttl < 60 || ttl > 86400 {
		return dnsRecord{}, &cloudError{
			http.StatusBadRequest,
			"InvalidParameter",
			"TTL must be between 60 and 86400 seconds",
		}
	}

	return dnsRecord{RR: name, Type: recordType, Value: value, TTL: ttl}, nil
}

// ---- RAM handlers ----

// handleRAMListUsers implements GET /v1/ram/users. It is only ever reached by a
// credential whose policy allows ram:ListUsers, which the control plane never
// mints: RenderPolicy appends an explicit deny for ram:* to every document.
func handleRAMListUsers(h *handler, _ *http.Request, _ *authContext) (int, map[string]any, *cloudError) {
	return http.StatusOK, map[string]any{
		"Users": map[string]any{"User": h.state.listRAMUsers()},
	}, nil
}

// ---- error helpers ----

// errInstanceNotFound is the Aliyun-shaped 404 for an unknown ECS instance.
func errInstanceNotFound(id string) *cloudError {
	return &cloudError{
		status:  http.StatusNotFound,
		code:    "InvalidInstance.NotFound",
		message: fmt.Sprintf("The specified instance %q does not exist", id),
	}
}

// errDomainNotFound is the Aliyun-shaped 404 for an unknown DNS zone.
func errDomainNotFound(zone string) *cloudError {
	return &cloudError{
		status:  http.StatusNotFound,
		code:    "InvalidDomain.NotFound",
		message: fmt.Sprintf("The specified domain %q does not exist", zone),
	}
}
