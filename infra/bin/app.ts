#!/usr/bin/env node
import { App } from "aws-cdk-lib";

import { DemoStack } from "../lib/demo-stack.js";

const app = new App();

new DemoStack(app, "LambdaMicrovmPackageInspector", {
  description:
    "Disposable EKS control plane for isolated npm inspection in Lambda MicroVMs",
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? "ap-northeast-1",
  },
});
