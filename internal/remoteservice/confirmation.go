package remoteservice

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"time"
)

// LocalPresence is implemented by target-local UI or physical-presence code.
// It must not consult the Coordinator to make the confirmation decision.
type LocalPresence interface {
	ConfirmServiceStart(context.Context, Target) error
}

type clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type confirmationState uint8

const (
	confirmationPending confirmationState = iota + 1
	confirmationConsumed
)

type confirmationRecord struct {
	target  Target
	expires time.Time
	state   confirmationState
}

// Confirmer owns ephemeral confirmations in the target-local process. Its
// state is intentionally not persisted: restart invalidates every capability.
type Confirmer struct {
	mu       sync.Mutex
	presence LocalPresence
	random   io.Reader
	clock    clock
	config   Config
	records  map[[32]byte]confirmationRecord
	inFlight int
}

// NewConfirmer creates a target-local confirmation authority.
func NewConfirmer(presence LocalPresence, config Config) (*Confirmer, error) {
	if presence == nil {
		return nil, &Error{Code: CodeInvalidRequest}
	}
	return newConfirmer(presence, rand.Reader, realClock{}, config)
}

func newConfirmer(presence LocalPresence, random io.Reader, clk clock, config Config) (*Confirmer, error) {
	if presence == nil || random == nil || clk == nil {
		return nil, &Error{Code: CodeInvalidRequest}
	}
	return &Confirmer{
		presence: presence,
		random:   random,
		clock:    clk,
		config:   config.normalized(),
		records:  make(map[[32]byte]confirmationRecord),
	}, nil
}

// Confirm requests local approval and mints a short-lived, single-use token.
func (c *Confirmer) Confirm(ctx context.Context, target Target) (ConfirmationToken, error) {
	var zero ConfirmationToken
	if ctx == nil {
		return zero, &Error{Code: CodeInvalidRequest}
	}
	if err := validateTarget(target); err != nil {
		return zero, err
	}

	now := c.clock.Now()
	c.mu.Lock()
	c.pruneLocked(now)
	if len(c.records)+c.inFlight >= c.config.MaxConfirmations {
		c.mu.Unlock()
		return zero, &Error{Code: CodeConfirmationCapacity}
	}
	c.inFlight++
	c.mu.Unlock()
	reserved := true
	defer func() {
		if !reserved {
			return
		}
		c.mu.Lock()
		c.inFlight--
		c.mu.Unlock()
	}()

	confirmCtx, cancel := context.WithTimeout(ctx, c.config.ConfirmationTimeout)
	defer cancel()
	if err := c.presence.ConfirmServiceStart(confirmCtx, target); err != nil {
		return zero, &Error{Code: contextCode(confirmCtx, CodeConfirmationDenied), Cause: err}
	}
	if err := confirmCtx.Err(); err != nil {
		return zero, &Error{Code: contextCode(confirmCtx, CodeConfirmationDenied), Cause: err}
	}

	for range 8 {
		if _, err := io.ReadFull(c.random, zero[:]); err != nil {
			return ConfirmationToken{}, &Error{Code: CodeConfirmationDenied, Cause: err}
		}
		digest := sha256.Sum256(zero[:])
		c.mu.Lock()
		if _, exists := c.records[digest]; exists {
			c.mu.Unlock()
			continue
		}
		c.records[digest] = confirmationRecord{
			target:  target,
			expires: c.clock.Now().Add(c.config.ConfirmationTTL),
			state:   confirmationPending,
		}
		c.inFlight--
		reserved = false
		c.mu.Unlock()
		return zero, nil
	}
	return ConfirmationToken{}, &Error{Code: CodeConfirmationDenied, Cause: errors.New("random capability collision")}
}

func (c *Confirmer) consume(target Target, token ConfirmationToken) error {
	if token == (ConfirmationToken{}) {
		return &Error{Code: CodeConfirmationInvalid}
	}
	digest := sha256.Sum256(token[:])
	now := c.clock.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	record, ok := c.records[digest]
	if !ok {
		c.pruneLocked(now)
		return &Error{Code: CodeConfirmationInvalid}
	}
	if !now.Before(record.expires) {
		delete(c.records, digest)
		return &Error{Code: CodeConfirmationExpired}
	}
	if record.state == confirmationConsumed {
		return &Error{Code: CodeConfirmationReplay}
	}
	if record.target != target {
		return &Error{Code: CodeConfirmationInvalid}
	}
	record.state = confirmationConsumed
	c.records[digest] = record
	return nil
}

func (c *Confirmer) pruneLocked(now time.Time) {
	for digest, record := range c.records {
		if !now.Before(record.expires) {
			delete(c.records, digest)
		}
	}
}
