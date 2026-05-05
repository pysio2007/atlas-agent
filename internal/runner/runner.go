package runner

import "context"

type Runner interface {
	Run(ctx context.Context, target string, options any) (any, error)
}
