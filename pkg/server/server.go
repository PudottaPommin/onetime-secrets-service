package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/alexedwards/flow"
)

const defaultReadHeaderTimeout = 5 * time.Second

type Server struct {
	ctx context.Context
	e   *flow.Mux
	srv *http.Server
}

func New(ctx context.Context, e *flow.Mux) *Server {
	return &Server{ctx: ctx, e: e, srv: nil}
}

func (s *Server) Ctx() context.Context { return s.ctx }

func (s *Server) E() *flow.Mux { return s.e }

func (s *Server) Run(addr string) error {
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           s.e,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
	}

	go func() {
		<-s.ctx.Done()
		_ = s.srv.Shutdown(context.Background())
	}()

	if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to run http server: %w", err)
	}
	return nil
}
