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

package dns_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gpu-ninja/loopy-dns/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/net/dns/dnsmessage"
)

func TestListenAndServe(t *testing.T) {
	logger := zaptest.NewLogger(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := dns.NewServer(logger, "test.zone.")
	go func() {
		if err := s.ListenAndServe(ctx, ":5300"); err != nil {
			logger.Error("Failed to listen and serve", zap.Error(err))
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("udp", "127.0.0.1:5300")
	require.NoError(t, err)
	defer conn.Close()

	t.Run("Valid query", func(t *testing.T) {
		query := &dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:               1,
				Response:         false,
				OpCode:           0,
				Authoritative:    true,
				RecursionDesired: true,
			},
			Questions: []dnsmessage.Question{{
				Name:  dnsmessage.MustNewName("test.zone."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			}},
		}
		packed, err := query.Pack()
		require.NoError(t, err)

		_, err = conn.Write(packed)
		require.NoError(t, err)

		responseBytes := make([]byte, 512)
		n, err := conn.Read(responseBytes)
		require.NoError(t, err)

		response := new(dnsmessage.Message)
		err = response.Unpack(responseBytes[:n])
		require.NoError(t, err)

		assert.Equal(t, uint16(1), response.Header.ID)
		assert.True(t, response.Header.Response)
		assert.Equal(t, dnsmessage.RCodeSuccess, response.Header.RCode)
		assert.Len(t, response.Answers, 1)

		answer := response.Answers[0].Body
		aRecord, ok := answer.(*dnsmessage.AResource)
		assert.True(t, ok)

		assert.Equal(t, []byte(net.IPv4(127, 0, 0, 1).To4()), aRecord.A[:])
	})

	t.Run("Invalid query", func(t *testing.T) {
		query := &dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:               1,
				Response:         false,
				OpCode:           0,
				Authoritative:    true,
				RecursionDesired: true,
			},
			Questions: []dnsmessage.Question{{
				Name:  dnsmessage.MustNewName("wrong.zone."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			}},
		}
		packed, err := query.Pack()
		require.NoError(t, err)

		_, err = conn.Write(packed)
		require.NoError(t, err)

		responseBytes := make([]byte, 512)
		n, err := conn.Read(responseBytes)
		require.NoError(t, err)

		response := new(dnsmessage.Message)
		err = response.Unpack(responseBytes[:n])
		require.NoError(t, err)

		assert.Equal(t, uint16(1), response.Header.ID)
		assert.True(t, response.Header.Response)
		assert.Equal(t, dnsmessage.RCodeNameError, response.Header.RCode)
	})

}
