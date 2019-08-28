package cauth

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"github.com/pkg/errors"
)

type authReq struct {
	Headers map[string]string `json:"headers"`
	Queries map[string]string `json:"queries"`
}

func (h *CAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, p := range h.Rules {
		cleanedPath := path.Clean(r.URL.Path)
		if !httpserver.Path(cleanedPath).Matches(p.Path) {
			continue
		}

		if r.Method == "OPTIONS" {
			continue
		}

		// Check excepted paths for this rule and allow access without validating any token
		var isExceptedPath bool
		for _, e := range p.ExceptedPaths {
			if httpserver.Path(r.URL.Path).Matches(e) {
				isExceptedPath = true
			}
		}
		if isExceptedPath {
			continue
		}
		if r.URL.Path == "/" && p.AllowRoot {
			// special case for protecting children of the root path, only allow access to base directory with directive `allowbase`
			continue
		}

		epData := authReq{
			Headers: map[string]string{},
			Queries: map[string]string{},
		}
		var missingRequiredField bool
		for _, h := range p.OptionalHeaders {
			s := r.Header.Get(h)
			if len(s) > 0 {
				epData.Headers[h] = s
			}
		}
		for _, q := range p.OptionalQueries {
			s := r.URL.Query().Get(q)
			if len(s) > 0 {
				epData.Queries[q] = s
			}
		}

		for _, h := range p.Headers {
			s := r.Header.Get(h)
			if len(s) > 0 {
				epData.Headers[h] = s
			} else {
				missingRequiredField = true
			}
		}
		for _, q := range p.Queries {
			s := r.URL.Query().Get(q)
			if len(s) > 0 {
				epData.Queries[q] = s
			} else {
				missingRequiredField = true
			}
		}
		for _, hq := range p.HeaderOrQuery {
			s := r.Header.Get(hq.header)
			if len(s) > 0 {
				epData.Headers[hq.header] = s
			} else {
				s = r.URL.Query().Get(hq.query)
				if len(s) > 0 {
					epData.Queries[hq.query] = s
				} else {
					missingRequiredField = true
				}
			}
		}
		if missingRequiredField {
			if p.Passthrough {
				continue
			}
			return handleUnauthorized(w, r, p, 401), nil
		}

		// Path matches, authorize
		headers, code, err := callEndpoint(r, p, &epData)
		if err != nil || code != 200 {
			if p.Passthrough {
				continue
			}
			return handleUnauthorized(w, r, p, code), nil
		}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return h.Next.ServeHTTP(w, r)
	}
	// pass request if no paths protected with JWT
	return h.Next.ServeHTTP(w, r)
}

func callEndpoint(r *http.Request, rule Rule, data *authReq) (headers map[string]string, code int, err error) {
	req := &http.Request{}
	req.URL, err = url.Parse(rule.Endpoint)
	if err != nil {
		err = errors.Wrap(err, "couldn't parse endpoint")
		return
	}
	req.Method = "POST"

	var body []byte
	body, err = json.Marshal(data)
	if err != nil {
		err = errors.Wrap(err, "couldn't marshal headers")
		return
	}
	req.Body = ioutil.NopCloser(bytes.NewReader(body))
	var res *http.Response
	res, err = httpCli.Do(req)
	if err != nil {
		err = errors.Wrap(err, "error contacting endpoint")
		return
	}
	code = res.StatusCode
	if res.StatusCode != 200 {
		err = errors.New("Not authorized")
		return
	}
	err = json.NewDecoder(res.Body).Decode(&headers)
	if err != nil {
		err = errors.Wrap(err, "couldn't decode response")
		return
	}
	return
}

// handleUnauthorized checks, which action should be performed if access was denied.
// It returns the status code and writes the Location header in case of a redirect.
// Possible caddy variables in the location value will be substituted.
func handleUnauthorized(w http.ResponseWriter, r *http.Request, rule Rule, code int) int {
	if rule.Redirect != "" {
		replacer := httpserver.NewReplacer(r, nil, "")
		http.Redirect(w, r, replacer.Replace(rule.Redirect), http.StatusSeeOther)
		return http.StatusSeeOther
	}

	if code == 0 {
		code = http.StatusUnauthorized
	}

	w.Header().Add("WWW-Authenticate", "Bearer error=\"invalid_token\"")
	return code
}

// handleForbidden checks, which action should be performed if access was denied.
// It returns the status code and writes the Location header in case of a redirect.
// Possible caddy variables in the location value will be substituted.
func handleForbidden(w http.ResponseWriter, r *http.Request, rule Rule) int {
	if rule.Redirect != "" {
		replacer := httpserver.NewReplacer(r, nil, "")
		http.Redirect(w, r, replacer.Replace(rule.Redirect), http.StatusSeeOther)
		return http.StatusSeeOther
	}
	w.Header().Add("WWW-Authenticate", "Bearer error=\"insufficient_scope\"")
	return http.StatusForbidden
}

// contains checks weather list is a slice ans containts the
// supplied string value.
func contains(list interface{}, value string) bool {
	switch l := list.(type) {
	case []interface{}:
		for _, v := range l {
			if v == value {
				return true
			}
		}
	}
	return false
}

func modTitleCase(s string) string {
	switch {
	case len(s) == 0:
		return s
	case len(s) == 1:
		return strings.ToUpper(s)
	default:
		return strings.ToUpper(string(s[0])) + s[1:]
	}
}
