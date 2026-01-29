package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/alexedwards/flow"
)

type Server struct {
	ctx context.Context
	e   *flow.Mux
	srv *http.Server
}

func New(ctx context.Context, e *flow.Mux) *Server {
	return &Server{ctx: ctx, e: e}
}

func (s *Server) Ctx() context.Context { return s.ctx }

func (s *Server) E() *flow.Mux { return s.e }

func (s *Server) Run(addr string) (err error) {
	s.srv = &http.Server{Addr: addr, Handler: s.e}

	go func() {
		<-s.ctx.Done()
		_ = s.srv.Shutdown(context.Background())
	}()

	if err = s.srv.ListenAndServe(); errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
