// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package aws

import (
	"context"
	"errors"
	"strconv"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/goformation/cloudformation"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/x-pack/functionbeat/core"
	"github.com/elastic/beats/x-pack/functionbeat/provider"
	"github.com/elastic/beats/x-pack/functionbeat/provider/aws/transformer"
)

// FlowLogsConfig is the configuration for the FlowLogs event type.
type FlowLogsConfig struct {
	Triggers     []*FlowLogsTriggerConfig `config:"triggers"`
	Description  string                   `config:"description"`
	Name         string                   `config:"name" validate:"nonzero,required"`
	LambdaConfig *lambdaConfig            `config:",inline"`
}

// FlowLogsTriggerConfig is the configuration for the specific triggers for cloudwatch.
type FlowLogsTriggerConfig struct {
	LogGroupName  logGroupName `config:"log_group_name" validate:"nonzero,required"`
	FilterPattern string       `config:"filter_pattern"`
}

// Validate validates the configuration.
func (cfg *FlowLogsConfig) Validate() error {
	if len(cfg.Triggers) == 0 {
		return errors.New("you need to specify at least one trigger")
	}
	return nil
}

// FlowLogs receives FlowLogs events from a lambda function and forward the logs to
// an Elasticsearch cluster.
type FlowLogs struct {
	log    *logp.Logger
	config *FlowLogsConfig
}

// NewFlowLogs create a new function to listen to cloudwatch logs events.
func NewFlowLogs(provider provider.Provider, cfg *common.Config) (provider.Function, error) {
	config := &FlowLogsConfig{
		LambdaConfig: DefaultLambdaConfig,
	}
	if err := cfg.Unpack(config); err != nil {
		return nil, err
	}
	return &FlowLogs{log: logp.NewLogger("flow_logs"), config: config}, nil
}

// Run start the AWS lambda handles and will transform any events received to the pipeline.
func (c *FlowLogs) Run(_ context.Context, client core.Client) error {
	lambda.Start(c.createHandler(client))
	return nil
}

func (c *FlowLogs) createHandler(
	client core.Client,
) func(request events.CloudwatchLogsEvent) error {
	return func(request events.CloudwatchLogsEvent) error {
		parsedEvent, err := request.AWSLogs.Parse()
		if err != nil {
			c.log.Errorf("Could not parse events from cloudwatch logs, error: %+v", err)
			return err
		}

		c.log.Debugf(
			"The handler receives %d events (logStream: %s, owner: %s, logGroup: %s, messageType: %s)",
			len(parsedEvent.LogEvents),
			parsedEvent.LogStream,
			parsedEvent.Owner,
			parsedEvent.LogGroup,
			parsedEvent.MessageType,
		)

		events := transformer.FlowLogs(parsedEvent)
		if err := client.PublishAll(events); err != nil {
			c.log.Errorf("Could not publish events to the pipeline, error: %+v", err)
			return err
		}
		client.Wait()
		return nil
	}
}

// Name returns the name of the function.
func (c FlowLogs) Name() string {
	return "flow_logs"
}

// Template returns the cloudformation template for configuring the service with the specified triggers.
func (c *FlowLogs) Template() *cloudformation.Template {
	prefix := func(suffix string) string {
		return "fnb" + c.config.Name + suffix
	}

	template := cloudformation.NewTemplate()
	for idx, trigger := range c.config.Triggers {
		// doc: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html
		template.Resources[prefix("Permission"+strconv.Itoa(idx))] = &cloudformation.AWSLambdaPermission{
			Action:       "lambda:InvokeFunction",
			FunctionName: cloudformation.GetAtt(prefix(""), "Arn"),
			Principal: cloudformation.Join("", []string{
				"logs.",
				cloudformation.Ref("AWS::Region"), // Use the configuration region.
				".",
				cloudformation.Ref("AWS::URLSuffix"), // awsamazon.com or .com.ch
			}),
			SourceArn: cloudformation.Join(
				"",
				[]string{
					"arn:",
					cloudformation.Ref("AWS::Partition"),
					":logs:",
					cloudformation.Ref("AWS::Region"),
					":",
					cloudformation.Ref("AWS::AccountId"),
					":log-group:",
					string(trigger.LogGroupName),
					":*",
				},
			),
		}

		// doc: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-subscriptionfilter.html
		template.Resources[prefix("SubscriptionFilter"+normalizeResourceName(string(trigger.LogGroupName)))] = &AWSLogsSubscriptionFilter{
			DestinationArn: cloudformation.GetAtt(prefix(""), "Arn"),
			FilterPattern:  trigger.FilterPattern,
			LogGroupName:   string(trigger.LogGroupName),
		}
	}
	return template
}

// LambdaConfig returns the configuration to use when creating the lambda.
func (c *FlowLogs) LambdaConfig() *lambdaConfig {
	return c.config.LambdaConfig
}
