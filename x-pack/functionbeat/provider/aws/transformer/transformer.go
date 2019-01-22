// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package transformer

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
)

// Centralize anything related to ECS into a common file.
// TODO: Look at the fields to align them with ECS.
// TODO: how to keep the fields in sync with AWS?
// TODO: api gateway proxy a lot more information is available.

// CloudwatchLogs takes an CloudwatchLogsData and transform it into a beat event.
func CloudwatchLogs(request events.CloudwatchLogsData) []beat.Event {
	events := make([]beat.Event, len(request.LogEvents))

	for idx, logEvent := range request.LogEvents {
		events[idx] = beat.Event{
			Timestamp: time.Now(), // TODO: time.Unix(logEvent.Timestamp, 0),
			Fields: common.MapStr{
				"message":              logEvent.Message,
				"id":                   logEvent.ID,
				"owner":                request.Owner,
				"log_stream":           request.LogStream,
				"log_group":            request.LogGroup,
				"message_type":         request.MessageType,
				"subscription_filters": request.SubscriptionFilters,
			},
		}
	}

	return events
}

// APIGatewayProxyRequest takes a web request on the api gateway proxy and transform it into a beat event.
func APIGatewayProxyRequest(request events.APIGatewayProxyRequest) beat.Event {
	return beat.Event{
		Timestamp: time.Now(),
		Fields: common.MapStr{
			"resource":          request.Resource,
			"path":              request.Path,
			"method":            request.HTTPMethod,
			"headers":           request.Headers,               // TODO: ECS map[string]
			"query_string":      request.QueryStringParameters, // TODO: map[string], might conflict with ECS
			"path_parameters":   request.PathParameters,
			"body":              request.Body, // TODO: could be JSON, json processor? could be used by other functions.
			"is_base64_encoded": request.IsBase64Encoded,
		},
	}
}

// KinesisEvent takes a kinesis event and create multiples beat events.
func KinesisEvent(request events.KinesisEvent) []beat.Event {
	events := make([]beat.Event, len(request.Records))
	for idx, record := range request.Records {
		events[idx] = beat.Event{
			Timestamp: time.Now(),
			Fields: common.MapStr{
				"event_id":         record.EventID,
				"event_name":       record.EventName,
				"event_source":     record.EventSource,
				"event_source_arn": record.EventSourceArn,
				"event_version":    record.EventVersion,
				"aws_region":       record.AwsRegion,
				// TODO: more meta data at KinesisRecord, need to check doc
			},
		}
	}
	return events
}

// SQS takes a SQS event and create multiples beat events.
func SQS(request events.SQSEvent) []beat.Event {
	events := make([]beat.Event, len(request.Records))
	for idx, record := range request.Records {
		events[idx] = beat.Event{
			Timestamp: time.Now(),
			Fields: common.MapStr{
				"message_id":       record.MessageId,
				"receipt_handle":   record.ReceiptHandle,
				"message":          record.Body,
				"attributes":       record.Attributes,
				"event_source":     record.EventSource,
				"event_source_arn": record.EventSourceARN,
				"aws_region":       record.AWSRegion,
			},
			// TODO: SQS message attributes missing, need to check doc
		}
	}
	return events
}

// FlowLogEvent contains all of the fields that can be parsed out of an AWS VPC
// flow log.
type FlowLogEvent struct {
	Key
	Value
	// Version            string
	AccountID string
}

type Key struct {
	InterfaceID        string
	SourceAddress      string
	DestinationAddress string
	SourcePort         int
	DestinationPort    int
	Protocol           string
	Action             string
	Status             string
}

type Value struct {
	Packets int64
	Bytes   int64
	Start   time.Time
	End     time.Time
}

func (v Value) Combine(other Value) Value {
	start := v.Start
	if other.Start.Before(v.Start) {
		start = other.Start
	}
	end := v.End
	if other.End.After(v.End) {
		end = other.End
	}
	nv := Value{
		Packets: v.Packets + other.Packets,
		Bytes:   v.Bytes + other.Bytes,
		Start:   start,
		End:     end,
	}

	return nv
}

// FlowLogs takes an CloudwatchLogsData formatted like a VPC flow log and
// transforms it into a beat event.
//
// TODO: Skip NODATA and SKIPEVENT logs
// TODO: Make inclusion of raw message optional
func FlowLogs(request events.CloudwatchLogsData) []beat.Event {
	allFlows := parseAll(request.LogEvents)
	flows := combine(allFlows)
	events := make([]beat.Event, len(flows))

	for idx, flow := range flows {
		events[idx] = beat.Event{
			Timestamp: time.Now(), // TODO: time.Unix(logEvent.Timestamp, 0),
			Fields: common.MapStr{
				// "message":              logEvent.Message,
				// "id":                   logEvent.ID,
				"owner":                request.Owner,
				"log_stream":           request.LogStream,
				"log_group":            request.LogGroup,
				"message_type":         request.MessageType,
				"subscription_filters": request.SubscriptionFilters,
				"account_id":           flow.AccountID,
				"interface_id":         flow.InterfaceID,
				"src_addr":             flow.SourceAddress,
				"dest_addr":            flow.DestinationAddress,
				"src_port":             flow.SourcePort,
				"dest_port":            flow.DestinationPort,
				"protocol":             flow.Protocol,
				"packets":              flow.Packets,
				"bytes":                flow.Bytes,
				"capture_start":        flow.Start,
				"capture_end":          flow.End,
				"action":               flow.Action,
				"direction":            parseDirection(flow.SourceAddress, flow.DestinationAddress),
			},
		}
	}

	return events
}

func parseAll(events []events.CloudwatchLogsLogEvent) []FlowLogEvent {
	flows := make([]FlowLogEvent, len(events))
	for i := range events {
		flows[i] = parseFlowLog(events[i].Message)
	}
	return flows
}

func combine(all []FlowLogEvent) []FlowLogEvent {
	acc := make(map[Key]Value)
	for _, flow := range all {
		existing, found := acc[flow.Key]
		if found {
			acc[flow.Key] = existing.Combine(flow.Value)
		} else {
			acc[flow.Key] = flow.Value
		}
	}

	combined := make([]FlowLogEvent, 0, len(acc))
	for k, v := range acc {
		combined = append(combined, FlowLogEvent{Key: k, Value: v})
	}

	return combined
}

var rfc1819 = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

var nets []*net.IPNet

func init() {
	for _, ip := range rfc1819 {
		_, ipnet, err := net.ParseCIDR(ip)
		if err != nil {
			panic(err)
		}
		nets = append(nets, ipnet)
	}
}

func isPublic(ip string) bool {
	return !isPrivate(ip)
}

func isPrivate(ip string) bool {
	for _, cidr := range nets {
		parsedIP := net.ParseIP(ip)
		if cidr.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func parseDirection(src, dest string) string {
	if isPrivate(src) {
		if isPublic(dest) {
			return "egress"
		}
		return "internal"
	}
	if isPrivate(dest) {
		return "ingress"
	}
	return "unknown"
}

func parseFlowLog(msg string) FlowLogEvent {
	fields := strings.Fields(msg)
	if len(fields) != 14 {
		return FlowLogEvent{}
	}
	srcPort, _ := strconv.Atoi(fields[5])
	if isEphemeral(srcPort) {
		srcPort = 0
	}
	destPort, _ := strconv.Atoi(fields[6])
	if isEphemeral(destPort) {
		destPort = 0
	}
	packets, _ := strconv.ParseInt(fields[8], 10, 64)
	bytes, _ := strconv.ParseInt(fields[9], 10, 64)
	start, _ := strconv.ParseInt(fields[10], 10, 64)
	end, _ := strconv.ParseInt(fields[11], 10, 64)
	evt := FlowLogEvent{
		// Version:            fields[0],
		AccountID: fields[1],
		Key: Key{
			InterfaceID:        fields[2],
			SourceAddress:      fields[3],
			DestinationAddress: fields[4],
			SourcePort:         srcPort,
			DestinationPort:    destPort,
			Protocol:           fields[7],
			Action:             fields[12],
			Status:             fields[13],
		},
		Value: Value{
			Packets: packets,
			Bytes:   bytes,
			Start:   time.Unix(start, 0),
			End:     time.Unix(end, 0),
		},
	}

	return evt
}

func isEphemeral(p int) bool {
	return p > 32768
}
