package cauth

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

var httpCli *http.Client

// CAuth represents configuration information for the middleware
type CAuth struct {
	Rules []Rule
	Next  httpserver.Handler
}

type HeaderQuery struct {
	header string
	query  string
}

// Rule represents the configuration for a site
type Rule struct {
	Path            string
	ExceptedPaths   []string
	Headers         []string
	OptionalHeaders []string
	Queries         []string
	OptionalQueries []string
	HeaderOrQuery   []HeaderQuery
	Redirect        string
	AllowRoot       bool
	Passthrough     bool
	StripHeader     bool
	Endpoint        string
}

func init() {
	// register a "generic" plugin, like a directive or middleware
	caddy.RegisterPlugin("cauth", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
	tr := &http.Transport{
		MaxIdleConnsPerHost: 20,
	}
	httpCli = &http.Client{
		Transport: tr,
	}
}

func setup(c *caddy.Controller) error {
	rules, err := parse(c)
	if err != nil {
		return err
	}

	c.OnStartup(func() error {
		fmt.Println("Custom Auth middleware is initiated")
		return nil
	})

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return &CAuth{
			Rules: rules,
			Next:  next,
		}
	})

	return nil
}

func parse(c *caddy.Controller) ([]Rule, error) {
	// This parses the following config blocks
	/*
		cauth /hello
		cauth /anotherpath
		cauth {
			path /hello
		}
	*/
	var rules []Rule
	//fmt.Printf("Remaining: %+v\n", c.RemainingArgs())
	for c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
			// no argument passed, check the config block
			var r = Rule{}
			for c.NextBlock() {
				switch c.Val() {
				case "path":
					if !c.NextArg() {
						// we are expecting a value
						return nil, c.ArgErr()
					}
					// return error if multiple paths in a block
					if len(r.Path) != 0 {
						return nil, c.ArgErr()
					}
					r.Path = c.Val()
					if c.NextArg() {
						// we are expecting only one value.
						return nil, c.ArgErr()
					}
				case "endpoint":
					if !c.NextArg() {
						// we are expecting a value
						return nil, c.ArgErr()
					}
					// return error if multiple paths in a block
					if len(r.Endpoint) != 0 {
						return nil, c.ArgErr()
					}
					r.Endpoint = c.Val()
					if c.NextArg() {
						// we are expecting only one value.
						return nil, c.ArgErr()
					}
				case "except":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					r.ExceptedPaths = append(r.ExceptedPaths, c.Val())
					if c.NextArg() {
						// except only allows one path per declaration
						return nil, c.ArgErr()
					}
				case "header":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					h := c.Val()

					if c.NextArg() && c.Val() == "optional" {
						r.OptionalHeaders = append(r.OptionalHeaders, h)
					} else {
						r.Headers = append(r.Headers, h)
					}

					if c.NextArg() {
						// except only allows one path per declaration
						return nil, c.ArgErr()
					}
				case "query":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					q := c.Val()

					if c.NextArg() && c.Val() == "optional" {
						r.OptionalQueries = append(r.OptionalQueries, q)
					} else {
						r.Queries = append(r.Queries, q)
					}
					if c.NextArg() {
						// except only allows one path per declaration
						return nil, c.ArgErr()
					}
				case "header_or_query":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					h := c.Val()
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					q := c.Val()
					if c.NextArg() {
						return nil, c.ArgErr()
					}
					r.HeaderOrQuery = append(r.HeaderOrQuery, HeaderQuery{header: h, query: q})
				case "allowroot":
					r.AllowRoot = true
				case "redirect":
					args1 := c.RemainingArgs()
					if len(args1) != 1 {
						return nil, c.ArgErr()
					}
					r.Redirect = args1[0]
				case "passthrough":
					r.Passthrough = true
				case "strip_header":
					r.StripHeader = true
				}
			}
			rules = append(rules, r)
		case 1:
			rules = append(rules, Rule{Path: args[0]})
			// one argument passed
			if c.NextBlock() {
				// path specified, no block required.
				return nil, c.ArgErr()
			}
		default:
			// we want only one argument max
			return nil, c.ArgErr()
		}
	}
	// check all rules at least have a path
	for _, r := range rules {
		if r.Path == "" {
			return nil, fmt.Errorf("Each rule must have a path")
		}
	}
	return rules, nil
}
