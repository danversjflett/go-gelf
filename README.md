go-gelf - GELF Library and Writer for Go
========================================

[GELF] (Graylog Extended Log Format) is an application-level logging
protocol that avoids many of the shortcomings of [syslog]. While it
can be run over any stream or datagram transport protocol, it has
special support ([chunking]) to allow long messages to be split over
multiple datagrams.

This repo is forked from
https://github.com/Graylog2/go-gelf/ using only a modified ``writer.go`` from the
``v1`` branch.

This allows go-gelf to integrate with zerolog. It will accept JSON-formatted
zerolog messages and will on-pass all zerolog context fields to Graylog.
