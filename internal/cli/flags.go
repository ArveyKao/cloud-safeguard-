package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// flagSet aliases flag.FlagSet for brevity in command implementations.
type flagSet = flag.FlagSet

// newFlagSet returns a quiet FlagSet; errors are surfaced through parseFlags so
// the CLI controls the "error: ..." formatting and exit code.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseFlags parses command flags and returns the positional arguments in
// order. Go's flag package stops parsing at the first positional argument, but
// the CLI accepts flags before or after positionals (e.g.
// "csg leases approve lea_1 --ttl 10m"), so arguments are reordered first.
// -h prints the command usage and returns errUsageShown (exit 0); any other
// parse error is a usage error (exit 2).
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	isBool := make(map[string]bool)
	fs.VisitAll(func(f *flag.Flag) {
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			isBool[f.Name] = true
		}
	})

	flagArgs := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		name := strings.TrimLeft(arg, "-")
		hasValue := false
		if idx := strings.IndexByte(name, '='); idx >= 0 {
			name = name[:idx]
			hasValue = true
		}
		flagArgs = append(flagArgs, arg)
		if isBool[name] || hasValue {
			continue
		}
		// A value-taking flag: consume the next argument as its value.
		if i+1 < len(args) {
			i++
			flagArgs = append(flagArgs, args[i])
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, errUsageShown
		}
		return nil, usagef("%v", err)
	}
	positionals = append(positionals, fs.Args()...)
	return positionals, nil
}

// parseDurationSeconds parses a duration flag/argument accepting "90s", "10m",
// "1h" or an integer number of seconds. It returns whole seconds, always > 0.
func parseDurationSeconds(value string) (int, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n <= 0 {
			return 0, fmt.Errorf("duration must be positive")
		}
		return n, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (use 90s, 10m, 1h or an integer number of seconds)", value)
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	secs := int(d / time.Second)
	if secs <= 0 {
		return 0, fmt.Errorf("duration %q is shorter than one second", value)
	}
	return secs, nil
}

// parseOptionalDurationSeconds parses an optional duration flag: empty means 0
// ("not provided" / "use server default").
func parseOptionalDurationSeconds(value string) (int, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	return parseDurationSeconds(value)
}

// parseRiskTier parses a risk tier flag (case-insensitive).
func parseRiskTier(value string) (model.RiskTier, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	r, ok := model.ParseRiskTier(v)
	if !ok {
		return "", fmt.Errorf("unknown risk tier %q (valid: low, medium, high, critical)", value)
	}
	return r, nil
}

// parseAgentRole parses an agent role flag (case-insensitive).
func parseAgentRole(value string) (model.AgentRole, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	role, ok := model.ParseAgentRole(v)
	if !ok {
		return "", fmt.Errorf("unknown role %q (valid: guest, member, administrator)", value)
	}
	return role, nil
}

// paramValues collects repeated --param key=value flags.
type paramValues map[string]string

// String implements flag.Value.
func (p *paramValues) String() string {
	if p == nil || len(*p) == 0 {
		return ""
	}
	parts := make([]string, 0, len(*p))
	for k, v := range *p {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

// Set implements flag.Value.
func (p *paramValues) Set(value string) error {
	key, val, ok := strings.Cut(value, "=")
	key = strings.TrimSpace(key)
	if !ok || key == "" {
		return fmt.Errorf("--param expects key=value (got %q)", value)
	}
	if *p == nil {
		*p = make(paramValues)
	}
	(*p)[key] = val
	return nil
}

// mapValue returns the params as a plain map (nil when empty).
func (p paramValues) mapValue() map[string]string {
	if len(p) == 0 {
		return nil
	}
	out := make(map[string]string, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

// stringSliceFlag collects repeated flags, splitting comma-separated values.
type stringSliceFlag []string

// String implements flag.Value.
func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }

// Set implements flag.Value.
func (s *stringSliceFlag) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

// values returns the collected strings (nil when empty).
func (s stringSliceFlag) values() []string {
	if len(s) == 0 {
		return nil
	}
	return append([]string(nil), s...)
}
