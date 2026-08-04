import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { describe, expect, it } from "vitest";

import { DemoStack } from "../lib/demo-stack.js";

const fixturePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "microvm-artifact",
);

/** Synthesize a deterministic test template without making AWS calls. */
function template(): Template {
  const app = new App();
  const stack = new DemoStack(app, "TestStack", {
    env: { account: "123456789012", region: "us-east-1" },
    microvmArtifactPath: fixturePath,
    microvmBaseImageVersion: "test-version",
  });
  return Template.fromStack(stack);
}

describe("DemoStack", () => {
  it("uses an EKS version that remains in standard support", () => {
    template().hasResourceProperties("Custom::AWSCDK-EKS-Cluster", {
      Config: Match.objectLike({ version: "1.34" }),
    });
  });

  it("runs the control plane workloads on one bounded ARM node", () => {
    template().hasResourceProperties("AWS::EKS::Nodegroup", {
      AmiType: "AL2023_ARM_64_STANDARD",
      DiskSize: 30,
      InstanceTypes: ["t4g.medium"],
      ScalingConfig: {
        DesiredSize: 1,
        MaxSize: 1,
        MinSize: 1,
      },
    });
  });

  it("expires EKS control plane logs after one week", () => {
    const resources = template().findResources("Custom::LogRetention");
    const serialized = JSON.stringify(resources);

    expect(serialized).toContain("/aws/eks/");
    expect(serialized).toContain("/cluster");
    expect(serialized).toContain('"RetentionInDays":7');
  });

  it("pins the MicroVM image to ARM64, bounded memory, and lifecycle hooks", () => {
    template().hasResourceProperties("AWS::Lambda::MicrovmImage", {
      AdditionalOsCapabilities: [],
      CpuConfigurations: [{ Architecture: "ARM_64" }],
      Resources: [{ MinimumMemoryInMiB: 1024 }],
      Hooks: {
        Port: 8080,
        MicrovmHooks: {
          Run: "ENABLED",
          Resume: "ENABLED",
          Suspend: "ENABLED",
          Terminate: "ENABLED",
          RunTimeoutInSeconds: 30,
          ResumeTimeoutInSeconds: 30,
          SuspendTimeoutInSeconds: 30,
          TerminateTimeoutInSeconds: 30,
        },
        MicrovmImageHooks: Match.objectLike({
          Ready: "ENABLED",
          Validate: "ENABLED",
        }),
      },
    });
  });

  it("routes runtime egress through an isolated VPC connector", () => {
    const synthesized = template();
    synthesized.hasResourceProperties("AWS::Lambda::NetworkConnector", {
      Configuration: {
        VpcEgressConfiguration: Match.objectLike({
          AssociatedComputeResourceTypes: ["MicroVm"],
          NetworkProtocol: "IPv4",
        }),
      },
    });
    synthesized.hasResourceProperties("AWS::EC2::SecurityGroup", {
      GroupDescription: Match.stringLikeRegexp("No ingress or egress"),
      SecurityGroupEgress: Match.anyValue(),
    });
  });

  it("allows network only while building the trusted MicroVM image", () => {
    const images = template().findResources("AWS::Lambda::MicrovmImage");
    const serialized = JSON.stringify(Object.values(images)[0]);
    expect(serialized).toContain("INTERNET_EGRESS");
    expect(serialized).not.toContain("DenyEgressConnector");
  });

  it("encrypts, versions, and blocks public access to reports", () => {
    template().hasResourceProperties("AWS::S3::Bucket", {
      BucketEncryption: {
        ServerSideEncryptionConfiguration: [
          { ServerSideEncryptionByDefault: { SSEAlgorithm: "AES256" } },
        ],
      },
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      },
      VersioningConfiguration: { Status: "Enabled" },
    });
  });

  it("does not create a MicroVM execution role", () => {
    const roles = template().findResources("AWS::IAM::Role");
    expect(
      Object.keys(roles).some((name) => name.includes("ExecutionRole")),
    ).toBe(false);
  });
});
