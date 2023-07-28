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

package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gpu-ninja/loopy-dns/dns"
	zaplogfmt "github.com/jsternberg/zap-logfmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	listenAddr := flag.String("listen", ":53", "The address to listen for DNS queries on")
	zone := flag.String("zone", "", "Optionally restrict DNS queries to this zone")

	flag.Parse()

	config := zap.NewProductionEncoderConfig()
	config.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendInt64(t.Unix())
	}

	logger := zap.New(zapcore.NewCore(
		zaplogfmt.NewEncoder(config),
		os.Stdout,
		zapcore.InfoLevel,
	))
	defer func() {
		_ = logger.Sync()
	}()

	if *zone != "" && !strings.HasSuffix(*zone, ".") {
		logger.Fatal("Zone must end with a period")
	}

	ctx, cancel := context.WithCancel(context.Background())

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		s := <-sigs
		logger.Info("Received signal, shutting down gracefully",
			zap.String("signal", s.String()))

		cancel()
	}()

	s := dns.NewServer(logger, *zone)

	if err := s.ListenAndServe(ctx, *listenAddr); err != nil {
		logger.Fatal("Failed to listen and serve", zap.Error(err))
	}
}
