import * as path from "node:path";

import { KubectlV34Layer } from "@aws-cdk/lambda-layer-kubectl-v34";
import {
  Arn,
  ArnFormat,
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  type StackProps,
  aws_ec2 as ec2,
  aws_ecr as ecr,
  aws_eks as eks,
  aws_iam as iam,
  aws_lambda as lambda,
  aws_logs as logs,
  aws_s3 as s3,
  aws_s3_assets as s3assets,
} from "aws-cdk-lib";
import type { Construct } from "constructs";

export interface DemoStackProps extends StackProps {
  /** Prepared zip input containing a root Dockerfile, runner source, and npm fixtures. */
  readonly microvmArtifactPath?: string;
  /** Pinned Lambda-managed AL2023 base image version discovered during preflight. */
  readonly microvmBaseImageVersion?: string;
}

/**
 * Provisions the disposable EKS control plane and Lambda MicroVM image resources.
 *
 * @remarks
 * The MicroVM egress connector uses an isolated subnet and a security group with
 * no outbound rules. The untrusted guest receives no execution role; IAM for ACK
 * and the orchestrator remains exclusively in EKS service accounts.
 */
export class DemoStack extends Stack {
  public constructor(scope: Construct, id: string, props: DemoStackProps = {}) {
    super(scope, id, props);

    const artifactPath = path.resolve(
      props.microvmArtifactPath ??
        String(
          this.node.tryGetContext("microvmArtifactPath") ??
            "../build/microvm-artifact",
        ),
    );
    const baseImageVersion =
      props.microvmBaseImageVersion ??
      String(this.node.tryGetContext("microvmBaseImageVersion") ?? "1.0");

    const vpc = new ec2.Vpc(this, "Vpc", {
      maxAzs: 2,
      natGateways: 1,
      subnetConfiguration: [
        { name: "public", subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
        {
          name: "eks",
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
          cidrMask: 24,
        },
        {
          name: "microvm-deny",
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 28,
        },
      ],
    });

    const microvmSecurityGroup = new ec2.SecurityGroup(
      this,
      "MicrovmDenyAllSecurityGroup",
      {
        vpc,
        allowAllOutbound: false,
        allowAllIpv6Outbound: false,
        description:
          "No ingress or egress for untrusted package inspection MicroVM ENIs",
      },
    );
    const isolatedSubnets = vpc.selectSubnets({
      subnetGroupName: "microvm-deny",
      onePerAz: true,
    });

    const connectorOperatorRole = new iam.Role(
      this,
      "NetworkConnectorOperatorRole",
      {
        assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
        managedPolicies: [
          iam.ManagedPolicy.fromAwsManagedPolicyName(
            "AWSLambdaNetworkConnectorOperatorPolicy",
          ),
        ],
      },
    );
    connectorOperatorRole.assumeRolePolicy?.addStatements(
      new iam.PolicyStatement({
        principals: [new iam.ServicePrincipal("lambda.amazonaws.com")],
        actions: ["sts:TagSession"],
      }),
    );

    const egressConnector = new lambda.CfnNetworkConnector(
      this,
      "DenyEgressConnector",
      {
        name: "package-inspector-deny-egress",
        operatorRole: connectorOperatorRole.roleArn,
        configuration: {
          vpcEgressConfiguration: {
            associatedComputeResourceTypes: ["MicroVm"],
            networkProtocol: "IPv4",
            securityGroupIds: [microvmSecurityGroup.securityGroupId],
            subnetIds: isolatedSubnets.subnetIds,
          },
        },
        tags: [{ key: "Project", value: "lambda-microvm-package-inspector" }],
      },
    );
    const egressConnectorARN =
      egressConnector.networkConnectorRef.networkConnectorArn;
    const buildEgressConnectorARN = `arn:${this.partition}:lambda:${this.region}:aws:network-connector:aws-network-connector:INTERNET_EGRESS`;

    const reportBucket = new s3.Bucket(this, "ReportBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      lifecycleRules: [
        {
          expiration: Duration.days(7),
          noncurrentVersionExpiration: Duration.days(1),
        },
      ],
      autoDeleteObjects: true,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const buildArtifact = new s3assets.Asset(this, "MicrovmBuildArtifact", {
      path: artifactPath,
    });
    const buildLogGroup = new logs.LogGroup(this, "MicrovmBuildLogs", {
      logGroupName: "/aws/lambda/microvms/package-inspector",
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const buildRole = new iam.Role(this, "MicrovmBuildRole", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
    });
    buildRole.assumeRolePolicy?.addStatements(
      new iam.PolicyStatement({
        principals: [new iam.ServicePrincipal("lambda.amazonaws.com")],
        actions: ["sts:TagSession"],
      }),
    );
    buildArtifact.grantRead(buildRole);
    buildLogGroup.grantWrite(buildRole);

    const microvmImage = new lambda.CfnMicrovmImage(this, "InspectorImage", {
      name: "npm-package-inspector",
      description:
        "Offline npm fixture inspector with a non-root package execution user",
      codeArtifact: { uri: buildArtifact.s3ObjectUrl },
      baseImageArn: `arn:${this.partition}:lambda:${this.region}:aws:microvm-image:al2023-1`,
      baseImageVersion,
      buildRoleArn: buildRole.roleArn,
      additionalOsCapabilities: [],
      cpuConfigurations: [{ architecture: "ARM_64" }],
      resources: [{ minimumMemoryInMiB: 1024 }],
      // Image creation is trusted build-time activity and must pull the pinned
      // container base plus Debian packages. Runtime MicroVMs use the separate
      // deny-egress connector passed by the Kubernetes orchestrator.
      egressNetworkConnectors: [buildEgressConnectorARN],
      environmentVariables: [],
      hooks: {
        port: 8080,
        microvmImageHooks: {
          ready: "ENABLED",
          readyTimeoutInSeconds: 120,
          validate: "ENABLED",
          validateTimeoutInSeconds: 120,
        },
        microvmHooks: {
          run: "ENABLED",
          runTimeoutInSeconds: 30,
          resume: "ENABLED",
          resumeTimeoutInSeconds: 30,
          suspend: "ENABLED",
          suspendTimeoutInSeconds: 30,
          terminate: "ENABLED",
          terminateTimeoutInSeconds: 30,
        },
      },
      logging: { cloudWatch: { logGroup: buildLogGroup.logGroupName } },
      tags: [{ key: "Project", value: "lambda-microvm-package-inspector" }],
    });

    const cluster = new eks.Cluster(this, "Cluster", {
      version: eks.KubernetesVersion.V1_34,
      kubectlLayer: new KubectlV34Layer(this, "KubectlLayer"),
      vpc,
      vpcSubnets: [{ subnetGroupName: "eks" }],
      endpointAccess: eks.EndpointAccess.PUBLIC_AND_PRIVATE,
      defaultCapacity: 0,
      clusterLogging: [
        eks.ClusterLoggingTypes.API,
        eks.ClusterLoggingTypes.AUDIT,
        eks.ClusterLoggingTypes.AUTHENTICATOR,
      ],
    });
    cluster.addNodegroupCapacity("SystemNodes", {
      amiType: eks.NodegroupAmiType.AL2023_ARM_64_STANDARD,
      instanceTypes: [new ec2.InstanceType("t4g.medium")],
      minSize: 1,
      desiredSize: 1,
      maxSize: 1,
      diskSize: 30,
      subnets: { subnetGroupName: "eks" },
    });

    new logs.LogRetention(this, "EksControlPlaneLogRetention", {
      logGroupName: `/aws/eks/${cluster.clusterName}/cluster`,
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const namespace = "package-inspector-system";
    const ackServiceAccount = cluster.addServiceAccount("AckServiceAccount", {
      name: "ack-lambdamicrovms-controller",
      namespace,
    });
    ackServiceAccount.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: [
          "lambda:RunMicrovm",
          "lambda:GetMicrovm",
          "lambda:ListMicrovms",
          "lambda:TerminateMicrovm",
          "lambda:GetMicrovmImage",
          "lambda:GetMicrovmImageVersion",
          "lambda:ListMicrovmImages",
          "lambda:ListMicrovmImageVersions",
          "lambda:TagResource",
          "lambda:UntagResource",
        ],
        resources: ["*"],
      }),
    );

    cluster.addHelmChart("LambdaMicrovmsAckController", {
      chart: "lambdamicrovms-chart",
      repository: "oci://public.ecr.aws/aws-controllers-k8s",
      version: "0.1.1",
      namespace,
      createNamespace: true,
      wait: true,
      values: {
        aws: { region: this.region },
        deletionPolicy: "delete",
        enableCARM: false,
        enableCrossNamespace: false,
        installScope: "namespace",
        watchNamespace: namespace,
        serviceAccount: {
          create: false,
          name: ackServiceAccount.serviceAccountName,
        },
        reconcile: { resources: ["Microvm"] },
      },
    });

    const controllerServiceAccount = cluster.addServiceAccount(
      "ControllerServiceAccount",
      {
        name: "package-inspection-controller",
        namespace,
      },
    );
    controllerServiceAccount.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ["lambda:CreateMicrovmAuthToken"],
        resources: [
          Arn.format(
            {
              service: "lambda",
              resource: "microvm",
              resourceName: "*",
              arnFormat: ArnFormat.COLON_RESOURCE_NAME,
            },
            this,
          ),
        ],
      }),
    );
    reportBucket.grantPut(controllerServiceAccount);

    const controllerRepository = new ecr.Repository(
      this,
      "ControllerRepository",
      {
        imageScanOnPush: true,
        emptyOnDelete: true,
        removalPolicy: RemovalPolicy.DESTROY,
        lifecycleRules: [{ maxImageCount: 5 }],
      },
    );

    new CfnOutput(this, "ClusterName", { value: cluster.clusterName });
    new CfnOutput(this, "ControllerRepositoryUri", {
      value: controllerRepository.repositoryUri,
    });
    new CfnOutput(this, "EgressConnectorArn", { value: egressConnectorARN });
    new CfnOutput(this, "MicrovmImageArn", {
      value: microvmImage.attrImageArn,
    });
    new CfnOutput(this, "MicrovmImageVersion", {
      value: microvmImage.attrLatestActiveImageVersion,
    });
    new CfnOutput(this, "ReportBucketName", { value: reportBucket.bucketName });
  }
}
