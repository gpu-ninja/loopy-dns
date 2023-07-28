/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright 2023 Damian Peckett <damian@peckett>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"
)

// Server is a ridiculously primitive DNS server that returns the loopback
// address for all A and AAAA record queries.
type Server struct {
	logger *zap.Logger
	zone   string
}

func NewServer(logger *zap.Logger, zone string) *Server {
	return &Server{
		logger: logger,
		zone:   zone,
	}
}

func (s *Server) ListenAndServe(ctx context.Context, listenAddr string) error {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr.String(), err)
	}

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	s.logger.Info("Listening for DNS requests", zap.String("addr", addr.String()))

	return s.handleRequests(ctx, conn)
}

func (s *Server) handleRequests(ctx context.Context, conn *net.UDPConn) error {
	for {
		query := make([]byte, 512)
		n, srcAddr, err := conn.ReadFromUDP(query)
		if errors.Is(err, net.ErrClosed) {
			return nil
		} else if err != nil {
			s.logger.Error("Failed to read from UDP connection", zap.Error(err))
			continue
		}

		go func() {
			if err := s.handleQuery(ctx, conn, srcAddr, query[:n]); err != nil {
				s.logger.Error("Failed to handle DNS query", zap.Error(err))
			}
		}()
	}
}

func (s *Server) handleQuery(ctx context.Context, conn *net.UDPConn, srcAddr *net.UDPAddr, query []byte) error {
	var p dnsmessage.Parser

	queryHeader, err := p.Start(query)
	if err != nil {
		return fmt.Errorf("failed to parse DNS query header: %w", err)
	}

	// Only support the single question queries for now.
	q, err := p.Question()
	if err != nil {
		return fmt.Errorf("failed to parse DNS question: %w", err)
	}

	response, err := s.buildResponse(queryHeader, q)
	if err != nil {
		return fmt.Errorf("failed to build DNS response: %w", err)
	}

	if _, err := conn.WriteToUDP(response, srcAddr); err != nil {
		return fmt.Errorf("failed to write DNS response: %w", err)
	}

	return nil
}

func (s *Server) buildResponse(queryHeader dnsmessage.Header, q dnsmessage.Question) ([]byte, error) {
	responseHeader := dnsmessage.Header{
		ID:                 queryHeader.ID,
		Response:           true,
		OpCode:             0,
		Authoritative:      true, // We're able to white label domains by always being authoritative
		Truncated:          false,
		RecursionDesired:   queryHeader.RecursionDesired,
		RecursionAvailable: false, // We are not recursing servers, so recursion is never available. Prevents DDOS
		RCode:              dnsmessage.RCodeSuccess,
	}

	answerBuilder, err := s.answerQuestion(&responseHeader, q)
	if err != nil {
		return nil, fmt.Errorf("failed to construct answer builder: %w", err)
	}

	b := dnsmessage.NewBuilder(nil, responseHeader)
	b.EnableCompression()

	if err := b.StartQuestions(); err != nil {
		return nil, err
	}

	if err := b.Question(q); err != nil {
		return nil, err
	}

	if err := b.StartAnswers(); err != nil {
		return nil, err
	}

	if err := answerBuilder(&b); err != nil {
		return nil, fmt.Errorf("failed to build answer: %w", err)
	}

	return b.Finish()
}

func (s *Server) answerQuestion(responseHeader *dnsmessage.Header, q dnsmessage.Question) (func(*dnsmessage.Builder) error, error) {
	noResponse := func(_ *dnsmessage.Builder) error { return nil }

	if s.zone != "" && !isDomainInZone(q.Name.String(), s.zone) {
		s.logger.Info("Received query for domain not in zone",
			zap.String("name", q.Name.String()), zap.String("type", q.Type.String()))

		responseHeader.RCode = dnsmessage.RCodeNameError
		return noResponse, nil
	}

	switch q.Type {
	case dnsmessage.TypeA:
		s.logger.Info("Received A query", zap.String("name", q.Name.String()))

		return func(b *dnsmessage.Builder) error {
			localIP := net.IPv4(127, 0, 0, 1)

			return b.AResource(dnsmessage.ResourceHeader{
				Name:   q.Name,
				Type:   dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				TTL:    300,
				Length: 0,
			}, ipV4ToAResource(localIP))
		}, nil
	case dnsmessage.TypeAAAA:
		s.logger.Info("Received AAAA query", zap.String("name", q.Name.String()))

		localIP := net.ParseIP("::1")

		return func(b *dnsmessage.Builder) error {
			return b.AAAAResource(dnsmessage.ResourceHeader{
				Name:   q.Name,
				Type:   dnsmessage.TypeAAAA,
				Class:  dnsmessage.ClassINET,
				TTL:    300,
				Length: 0,
			}, ipV6ToAAAAResource(localIP))
		}, nil
	default:
		s.logger.Info("Received unsupported query",
			zap.String("name", q.Name.String()), zap.String("type", q.Type.String()))

		responseHeader.RCode = dnsmessage.RCodeNotImplemented
		return noResponse, nil
	}
}

func ipV4ToAResource(ip net.IP) dnsmessage.AResource {
	var resource dnsmessage.AResource
	copy(resource.A[:], ip.To4())
	return resource
}

func ipV6ToAAAAResource(ip net.IP) dnsmessage.AAAAResource {
	var resource dnsmessage.AAAAResource
	copy(resource.AAAA[:], ip)
	return resource
}

func isDomainInZone(name, zone string) bool {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	nameParts := strings.Split(name, ".")
	zoneParts := strings.Split(zone, ".")

	for i, j := len(nameParts)-1, len(zoneParts)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if nameParts[i] != zoneParts[j] {
			return false
		}
	}

	return true
}
