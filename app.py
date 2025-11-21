#!/usr/bin/env python3
import os
import aws_cdk as cdk
from cdk_nag import AwsSolutionsChecks
from datazone.sagemaker_unified_studio_stack import SageMakerUnifiedStudioDataZoneStack

app = cdk.App()

# Get account and region values from environment variables
account = os.getenv("CDK_DEFAULT_ACCOUNT")
region = os.getenv("CDK_DEFAULT_REGION")

# Deploy the SageMaker Unified Studio DataZone stack with dynamic env from environment variables
stack = SageMakerUnifiedStudioDataZoneStack(
    app,
    "SageMakerUnifiedStudioDataZoneStack",
    env=cdk.Environment(
        account=account,
        region=region
    ),
    description="SageMaker Unified Studio using DataZone V2 with All Capabilities project profile"
)

app.synth()