package mockcloud

import (
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Mock S3 and IAM for AWS mock accounts (CONTRACT §17.13). Requests carry a
// mock token like the Alibaba routes; the token's policy is checked against
// the S3 action and the bucket or object ARN, so a read credential lists and
// reads but cannot write, and nothing reaches IAM.

const (
	s3Service  = "s3"
	iamService = "iam"
	// mockBucket is the fixture bucket the demo uses.
	mockBucket = "claudecode"
	// maxObjectKey bounds an object key, as S3 does.
	maxObjectKey = 1024
)

// s3State is the in-memory bucket fixture.
type s3State struct {
	mu      sync.Mutex
	buckets map[string]map[string]string
}

func newS3State() *s3State {
	return &s3State{buckets: map[string]map[string]string{
		mockBucket: {
			"README.md":      "Cloud Safeguard mock bucket.\n",
			"notes/plan.txt": "1. read 2. never write with a read key\n",
		},
		"other-team-bucket": {"secret.txt": "not yours\n"},
	}}
}

func s3BucketARN(r *http.Request) string { return "arn:aws:s3:::" + r.PathValue("bucket") }

func s3ObjectARN(r *http.Request) string {
	return "arn:aws:s3:::" + r.PathValue("bucket") + "/" + r.PathValue("key")
}

func errNoSuchBucket(bucket string) *cloudError {
	return &cloudError{status: http.StatusNotFound, code: "NoSuchBucket", message: "The specified bucket does not exist: " + bucket}
}

func errNoSuchKey(key string) *cloudError {
	return &cloudError{status: http.StatusNotFound, code: "NoSuchKey", message: "The specified key does not exist: " + key}
}

func validObjectKey(key string) bool {
	return key != "" && len(key) <= maxObjectKey && !strings.Contains(key, "..") && !strings.HasPrefix(key, "/")
}

func (h *handler) registerAWS(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/s3/buckets/{bucket}/objects", h.wrap(route{
		service: s3Service, action: "s3:ListBucket",
		resource: func(r *http.Request, _ *authContext) string { return s3BucketARN(r) },
		handle: func(h *handler, r *http.Request, _ *authContext) (int, map[string]any, *cloudError) {
			h.s3.mu.Lock()
			defer h.s3.mu.Unlock()
			objects, ok := h.s3.buckets[r.PathValue("bucket")]
			if !ok {
				return 0, nil, errNoSuchBucket(r.PathValue("bucket"))
			}
			keys := make([]string, 0, len(objects))
			for k := range objects {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			contents := make([]map[string]any, 0, len(keys))
			for _, k := range keys {
				contents = append(contents, map[string]any{"Key": k, "Size": len(objects[k])})
			}
			return http.StatusOK, map[string]any{"Name": r.PathValue("bucket"), "Contents": contents}, nil
		},
	}))
	object := func(method, action string, handle func(objects map[string]string, key string, r *http.Request) (int, map[string]any, *cloudError)) {
		mux.HandleFunc(method+" /v1/s3/buckets/{bucket}/objects/{key...}", h.wrap(route{
			service: s3Service, action: action,
			resource: func(r *http.Request, _ *authContext) string { return s3ObjectARN(r) },
			handle: func(h *handler, r *http.Request, _ *authContext) (int, map[string]any, *cloudError) {
				key := r.PathValue("key")
				if !validObjectKey(key) {
					return 0, nil, &cloudError{status: http.StatusBadRequest, code: "InvalidArgument", message: "invalid object key"}
				}
				h.s3.mu.Lock()
				defer h.s3.mu.Unlock()
				objects, ok := h.s3.buckets[r.PathValue("bucket")]
				if !ok {
					return 0, nil, errNoSuchBucket(r.PathValue("bucket"))
				}
				return handle(objects, key, r)
			},
		}))
	}
	object(http.MethodGet, "s3:GetObject", func(objects map[string]string, key string, _ *http.Request) (int, map[string]any, *cloudError) {
		body, ok := objects[key]
		if !ok {
			return 0, nil, errNoSuchKey(key)
		}
		return http.StatusOK, map[string]any{"Key": key, "Body": body}, nil
	})
	object(http.MethodPut, "s3:PutObject", func(objects map[string]string, key string, r *http.Request) (int, map[string]any, *cloudError) {
		var in struct {
			Body string `json:"Body"`
		}
		if cerr := readJSONBody(r, &in); cerr != nil {
			return 0, nil, cerr
		}
		objects[key] = in.Body
		return http.StatusOK, map[string]any{"Key": key, "Size": len(in.Body)}, nil
	})
	object(http.MethodDelete, "s3:DeleteObject", func(objects map[string]string, key string, _ *http.Request) (int, map[string]any, *cloudError) {
		delete(objects, key)
		return http.StatusOK, map[string]any{"Key": key, "Deleted": true}, nil
	})
	// IAM is reachable but never allowed: every AWS credential carries a
	// deny for iam:* (CONTRACT §17.13), so this route always answers 403.
	mux.HandleFunc("GET /v1/iam/users", h.wrap(route{
		service: iamService, action: "iam:ListUsers",
		resource: func(_ *http.Request, _ *authContext) string { return "*" },
		handle: func(_ *handler, _ *http.Request, _ *authContext) (int, map[string]any, *cloudError) {
			return http.StatusOK, map[string]any{"Users": []any{map[string]any{"UserName": "admin"}}}, nil
		},
	}))
}
