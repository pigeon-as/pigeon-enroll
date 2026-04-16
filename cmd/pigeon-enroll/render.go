package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"

	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
	"github.com/pigeon-as/pigeon-enroll/internal/pki"
	pb "github.com/pigeon-as/pigeon-enroll/proto/enroll/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func cmdRender(args []string) int {
	flags := newFlagSet("render")
	addr := flags.String("addr", "", "Enrollment server address (host:port)")
	tlsBundle := flags.String("tls", "", "Path to client TLS certificate bundle (PEM)")
	name := flags.String("name", "", "Template name to render")
	output := flags.String("output", "", "Path to write rendered output")
	insecureFlag := flags.Bool("insecure", false, "Skip TLS certificate verification")
	flags.Parse(args)

	if *addr == "" || *tlsBundle == "" || *name == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "usage: pigeon-enroll render -addr=<host:port> -tls=<bundle> -name=<template> -output=<path> [-insecure]")
		return 1
	}

	bundlePEM, err := os.ReadFile(*tlsBundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read TLS bundle: %v\n", err)
		return 1
	}
	key, cert, caPool, err := pki.LoadClientBundle(bundlePEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load TLS bundle: %v\n", err)
		return 1
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key,
		}},
		RootCAs:    caPool,
		ServerName: "pigeon-enroll",
	}
	if *insecureFlag {
		fmt.Fprintln(os.Stderr, "WARNING: TLS verification disabled — do not use in production")
		tlsCfg.InsecureSkipVerify = true
	}

	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))

	conn, err := grpc.NewClient(*addr, dialOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gRPC connect: %v\n", err)
		return 1
	}
	defer conn.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	client := pb.NewEnrollmentServiceClient(conn)
	resp, err := client.Render(ctx, &pb.RenderRequest{Name: *name})
	if err != nil {
		fmt.Fprintf(os.Stderr, "render failed: %v\n", err)
		return 1
	}

	if err := atomicfile.Write(*output, []byte(resp.Content), 0640); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", *output, err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "rendered %s → %s\n", *name, *output)
	return 0
}
