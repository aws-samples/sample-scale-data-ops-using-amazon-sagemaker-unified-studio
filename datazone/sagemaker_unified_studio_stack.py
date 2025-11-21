import aws_cdk as cdk
import logging
from aws_cdk import (
    aws_datazone as datazone,
    aws_iam as iam,
    aws_ec2 as ec2,
    aws_s3 as s3,
    CfnParameter,
    CfnCondition,
    CfnOutput,
    Fn,
    custom_resources as cr,
    aws_lambda as _lambda,
    aws_lakeformation as lakeformation,
)
from constructs import Construct
from typing import Dict, List
import json

# Configure module-level logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)  # Adjust log level as needed

class SageMakerUnifiedStudioDataZoneStack(cdk.Stack):

    def create_domain_exec_role(self):
        """Create the SageMaker Domain execution IAM role."""
        self.domain_exec_role = iam.Role(
            self,
            "AmazonSageMakerDomainExecution",
            role_name="AmazonSageMakerDomainExecution",
            path="/service-role/",
            assumed_by=iam.ServicePrincipal(
                "datazone.amazonaws.com",
                conditions={
                    "StringEquals": {"aws:SourceAccount": self.account},
                    "ForAllValues:StringLike": {"aws:TagKeys": ["datazone*"]},
                },
            ),
        )
        self.domain_exec_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/SageMakerStudioDomainExecutionRolePolicy"
            )
        )
        cfn_exec_role: iam.CfnRole = self.domain_exec_role.node.default_child
        cfn_exec_role.add_override(
            "Properties.AssumeRolePolicyDocument.Statement.0.Action",
            ["sts:AssumeRole", "sts:TagSession", "sts:SetContext"],
        )
        return self.domain_exec_role

    def create_domain_service_role(self):
        """Create the SageMaker Domain service IAM role."""
        self.domain_service_role = iam.Role(
            self,
            "AmazonSageMakerDomainService",
            role_name="AmazonSageMakerDomainService",
            path="/service-role/",
            assumed_by=iam.ServicePrincipal(
                "datazone.amazonaws.com",
                conditions={"StringEquals": {"aws:SourceAccount": self.account}},
            ),
        )
        self.domain_service_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/SageMakerStudioDomainServiceRolePolicy"
            )
        )
        return self.domain_service_role
    
    
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        domain_execution_role = self.create_domain_exec_role()
        domain_service_role = self.create_domain_service_role()

        # Remove the VPC parameter and create VPC with hardcoded CIDR
        self.vpc = ec2.Vpc(
            self, "SageMakerUnifiedStudioVPC",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),  # Use hardcoded CIDR
            max_azs=2,  # Use hardcoded value
            enable_dns_hostnames=True,
            enable_dns_support=True,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="PublicSubnet",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="PrivateSubnet",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="IsolatedSubnet",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24,
                ),
            ],
            nat_gateways=1,  # Use hardcoded value
        )

        logger.info(f"Created VPC: {self.vpc.vpc_id}")

        # --- Security Groups ---
        # Domain
        self.sagemaker_domain_sg = ec2.SecurityGroup(
            self, "SageMakerDomainSecurityGroup",
            vpc=self.vpc,
            description="Security group for SageMaker Unified Studio Domain",
            allow_all_outbound=True,
        )
        # Spaces
        self.sagemaker_spaces_sg = ec2.SecurityGroup(
            self, "SageMakerSpacesSecurityGroup",
            vpc=self.vpc,
            description="Security group for SageMaker Unified Studio Spaces",
            allow_all_outbound=True,
        )
        self.sagemaker_spaces_sg.add_ingress_rule(
            peer=self.sagemaker_domain_sg,
            connection=ec2.Port.all_traffic(),
            description="Allow traffic from SageMaker Domain"
        )
        self.sagemaker_domain_sg.add_ingress_rule(
            peer=self.sagemaker_spaces_sg,
            connection=ec2.Port.all_traffic(),
            description="Allow traffic from SageMaker Spaces"
        )
        # VPC Endpoints
        self.vpc_endpoint_sg = ec2.SecurityGroup(
            self, "VPCEndpointSecurityGroup",
            vpc=self.vpc,
            description="Security group for VPC Endpoints",
            allow_all_outbound=False,
        )
        self.vpc_endpoint_sg.add_ingress_rule(
            peer=self.sagemaker_domain_sg,
            connection=ec2.Port.tcp(443),
            description="HTTPS from SageMaker Domain"
        )
        self.vpc_endpoint_sg.add_ingress_rule(
            peer=self.sagemaker_spaces_sg,
            connection=ec2.Port.tcp(443),
            description="HTTPS from SageMaker Spaces"
        )
        # DataZone
        self.datazone_sg = ec2.SecurityGroup(
            self, "DataZoneSecurityGroup",
            vpc=self.vpc,
            description="Security group for DataZone resources",
            allow_all_outbound=True,
        )
        self.datazone_sg.add_ingress_rule(
            peer=self.sagemaker_domain_sg,
            connection=ec2.Port.tcp(443),
            description="HTTPS from SageMaker Domain"
        )
        self.datazone_sg.add_ingress_rule(
            peer=self.sagemaker_spaces_sg,
            connection=ec2.Port.tcp(443),
            description="HTTPS from SageMaker Spaces"
        )

        # --- VPC Endpoints ---
        self.s3_endpoint = self.vpc.add_gateway_endpoint(
            "S3GatewayEndpoint",
            service=ec2.GatewayVpcEndpointAwsService.S3,
            subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)]
        )
        self.dynamodb_endpoint = self.vpc.add_gateway_endpoint(
            "DynamoDBGatewayEndpoint",
            service=ec2.GatewayVpcEndpointAwsService.DYNAMODB,
            subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)]
        )
        vpc_endpoints = [
            # SageMaker endpoints
            ("SageMakerAPI", ec2.InterfaceVpcEndpointAwsService.SAGEMAKER_API),
            ("SageMakerRuntime", ec2.InterfaceVpcEndpointAwsService.SAGEMAKER_RUNTIME),
            ("SageMakerStudio", ec2.InterfaceVpcEndpointAwsService.SAGEMAKER_STUDIO),
            # AWS Core Services
            ("STS", ec2.InterfaceVpcEndpointAwsService.STS),
            ("SSM", ec2.InterfaceVpcEndpointAwsService.SSM),
            ("SSMMessages", ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES),
            ("EC2Messages", ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES),
            # CloudWatch and Logs
            ("CloudWatch", ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH),
            ("CloudWatchLogs", ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS),
            ("CloudWatchEvents", ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_EVENTS),
            # ECR for container images
            ("ECRApi", ec2.InterfaceVpcEndpointAwsService.ECR),
            ("ECRDocker", ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER),
            # KMS for encryption
            ("KMS", ec2.InterfaceVpcEndpointAwsService.KMS),
            # Secrets Manager
            ("SecretsManager", ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER),
        ]
        self.interface_endpoints = {}
        for name, service in vpc_endpoints:
            endpoint = self.vpc.add_interface_endpoint(
                f"{name}VPCEndpoint",
                service=service,
                subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
                security_groups=[self.vpc_endpoint_sg],
                private_dns_enabled=True,
            )
            self.interface_endpoints[name] = endpoint

        # Optionally, DataZone endpoints if available
        try:
            self.datazone_endpoint = ec2.InterfaceVpcEndpoint(
                self, "DataZoneVPCEndpoint",
                vpc=self.vpc,
                service=ec2.InterfaceVpcEndpointService(
                    f"com.amazonaws.{self.region}.datazone", 443
                ),
                subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
                security_groups=[self.vpc_endpoint_sg],
                private_dns_enabled=True,
            )
            self.datazone_fips_endpoint = ec2.InterfaceVpcEndpoint(
                self, "DataZoneFIPSVPCEndpoint",
                vpc=self.vpc,
                service=ec2.InterfaceVpcEndpointService(
                    f"com.amazonaws.{self.region}.datazone-fips", 443
                ),
                subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
                security_groups=[self.vpc_endpoint_sg],
                private_dns_enabled=True,
            )
            logger.info("Created DataZone VPC endpoints")
        except Exception:
            logger.warning(f"DataZone VPC endpoints not available in region {self.region}: {e}")

        logger.info(f"Finished VPC networking and endpoint setup: VPC={self.vpc.vpc_id}")
        #logger.info(f"Created VPC: {vpc.vpc_id}")

        # Create S3 bucket for domain artifacts
        domain_bucket = s3.Bucket(
            self, "SageMakerUnifiedStudioBucket",
            bucket_name=f"sagemaker-unified-studio-{self.account}-{self.region}",
            versioned=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )
        logger.info(f"Created S3 Bucket: {domain_bucket.bucket_name}")

        # ------------------------------------------------------------------------
        # SageMaker Studio Data-Transfer Role
        # ------------------------------------------------------------------------
        logger.info("Creating SageMaker Studio Data Transfer Role")
        datatransfer_principal = iam.CompositePrincipal(
            iam.ServicePrincipal("redshift.amazonaws.com"),
            iam.ServicePrincipal("glue.amazonaws.com"),
        )

        datatransfer_role = iam.Role(
            self,
            "SageMakerStudioDataTransferRole",
            assumed_by=datatransfer_principal,
            role_name="SageMakerStudioDataTransferRole",
        )
        
        lake_policy = iam.Policy(
            self,
            "LakeFormationGlueAccess",
            policy_name="LakeFormationGlueAccess",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "lakeformation:ListPermissions",
                        "lakeformation:ListLakeFormationOptIns",
                        "lakeformation:CreateLakeFormationOptIn",
                        "lakeformation:ListResources",
                        "lakeformation:RegisterResource",
                        "lakeformation:GrantPermissions",
                        "glue:GetDatabase",
                        "glue:GetTable",
                        "glue:GetTables",
                        "iam:GetRole",
                        "iam:PassRole",
                        "iam:GetRolePolicy",
                        "iam:PutRolePolicy",
                    ],
                    resources=["*"],
                )
            ],
        )
        lake_policy.attach_to_role(datatransfer_role)
        lake_policy.node.add_dependency(datatransfer_role)

        CfnOutput(
            self,
            "DataTransferRoleArn",
            value=datatransfer_role.role_arn,
        )
        logger.info("Created CfnOutput for Data Transfer Role ARN")

        # Create DataZone Domain
        datazone_domain = datazone.CfnDomain(
            self, "SageMakerUnifiedStudioDomain",
            name="sagemaker-unified-studio",
            description="SageMaker Unified Studio Domain with All Capabilities",
            domain_execution_role=domain_execution_role.role_arn,
            service_role=domain_service_role.role_arn, 
            domain_version="V2",
            single_sign_on=datazone.CfnDomain.SingleSignOnProperty(
                type='IAM_IDC', #self.config_data.sso.type,
                user_assignment='MANUAL' #self.config_data.sso.user_assignment,
            ),
            tags=[
                {"key": "Purpose", "value": "SageMaker-Unified-Studio"},
                {"key": "DomainType", "value": "DataZone-V2"}
            ]
        )
        datazone_domain.node.add_dependency(domain_execution_role)
        datazone_domain.node.add_dependency(domain_service_role)
        logger.info(f"Created DataZone Domain: {datazone_domain.name}")
        
        # SageMaker Query Execution Role
        query_execution_role = iam.Role(
            self, "AmazonSageMakerQueryExecutionRole",
            path="/service-role/",
            role_name="AmazonSageMakerQueryExecution",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("lakeformation.amazonaws.com"),
                iam.ServicePrincipal("glue.amazonaws.com"),
                iam.ServicePrincipal("athena.amazonaws.com")
            ),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/SageMakerStudioQueryExecutionRolePolicy"),
            ],
        )
        logger.info(f"Created Query Execution Role: {query_execution_role.role_name}")

        # SageMaker Provisioning Role
        provisioning_role = iam.Role(
            self, "AmazonSageMakerProvisioningRole",
            path="/service-role/",
            role_name=f"AmazonSageMakerProvisioning-{self.account}",
            assumed_by=iam.ServicePrincipal("datazone.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/SageMakerStudioProjectProvisioningRolePolicy"),
            ],
            inline_policies={
                "QueryExecutionRolePermissions": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            sid="IamRolePermissionsForQueryExecution",
                            effect=iam.Effect.ALLOW,
                            actions=["iam:PassRole", "iam:GetRole"],
                            resources=[query_execution_role.role_arn],
                        ),
                    ]
                ),
            },
        )
        provisioning_role.node.add_dependency(query_execution_role)
        logger.info(f"Created Provisioning Role: {provisioning_role.role_name}")

        # Parameter and condition to optionally create SageMaker Manage Access Role
        create_sagemaker_role = CfnParameter(
            self, "CreateSageMakerRole", type="String", allowed_values=["true", "false"], default="true"
        )
        sagemaker_condition = CfnCondition(
            self, "IsSageMaker",
            expression=Fn.condition_equals(create_sagemaker_role.value_as_string, "true"),
        )

        # SageMaker Manage Access Role (conditionally created)
        sagemaker_role = iam.Role(
            self,
            "SageMakerManageAccessRole",
            path="/service-role/",
            role_name=f"AmazonSageMakerManageAccess-{self.region}-{self.account}",
            assumed_by=iam.ServicePrincipal(
                service="datazone.amazonaws.com",
                conditions={
                    "StringEquals": {"aws:SourceAccount": self.account},
                    "ArnEquals": {"aws:SourceArn": datazone_domain.attr_arn},
                },
            ),
           
        )
        sagemaker_role.node.default_child.cfn_options.condition = sagemaker_condition

        # Attach managed policies to SageMaker Manage Access Role
        for policy_name in [
            "service-role/AmazonDataZoneGlueManageAccessRolePolicy",
            "service-role/AmazonDataZoneRedshiftManageAccessRolePolicy",
            "AmazonDataZoneSageMakerManageAccessRolePolicy",
        ]:
            sagemaker_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name(policy_name))
            logger.info(f"Attached managed policy {policy_name} to SageMaker Access Role")

        # Attach inline Secrets Manager permissions policy with DataZone domain tag condition
        secrets_policy = iam.Policy(
            self,
            "RedshiftSecretStatement",
            statements=[
                iam.PolicyStatement(
                    sid="GetSecretValuePermissions",
                    effect=iam.Effect.ALLOW,
                    actions=["secretsmanager:GetSecretValue"],
                    resources=["*"],
                    conditions={
                        "StringEquals": {
                            "secretsmanager:ResourceTag/AmazonDataZoneDomain": datazone_domain.attr_id
                        }
                    },
                )
            ],
        )
        secrets_policy.attach_to_role(sagemaker_role)
        logger.info("Attached RedshiftSecretStatement policy to SageMaker Access Role")

        # CfnOutput for SageMaker Access Role ARN
        CfnOutput(
            self,
            "SageMakerAccessRoleArn",
            value=sagemaker_role.role_arn,
            condition=sagemaker_condition,
        )
        logger.info("Created CfnOutput for SageMaker Access Role ARN")

        # Get private subnets for SageMaker
        private_subnets = self.vpc.private_subnets
        subnet_ids = [subnet.subnet_id for subnet in private_subnets]
        logger.info(f"Private Subnets: {subnet_ids}")

        # Create LakeFormation settings resource
        lake_formation_settings = cr.AwsCustomResource(
            self, "LakeFormationSettings",
            on_create=cr.AwsSdkCall(
                service="lakeformation",
                action="putDataLakeSettings",
                parameters={
                    "DataLakeSettings": {
                        "DataLakeAdmins": [
                            {
                                "DataLakePrincipalIdentifier": sagemaker_role.role_arn
                            },
                            {
                                "DataLakePrincipalIdentifier": f"arn:aws:iam::{self.account}:role/Admin"
                            }
                        ],
                        "DefaultResourceAccessRole": sagemaker_role.role_arn,
                        "AllowExternalDataFiltering": False,
                        "ExternalDataFilteringAllowList": [],
                        "CreateDatabaseDefaultPermissions": [
                            {
                                "Principal": {
                                    "DataLakePrincipalIdentifier": "IAM_ALLOWED_PRINCIPALS"
                                },
                                "Permissions": ["ALL"]
                            }
                        ],
                        "CreateTableDefaultPermissions": [
                            {
                                "Principal": {
                                    "DataLakePrincipalIdentifier": "IAM_ALLOWED_PRINCIPALS"
                                },
                                "Permissions": ["ALL"]
                            }
                        ],
                    }
                },
                physical_resource_id=cr.PhysicalResourceId.of("lakeformation-iam-settings")
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=[
                        "lakeformation:PutDataLakeSettings",
                        "lakeformation:GetDataLakeSettings",
                    ],
                    resources=["*"]
                )
            ])
        )

        lake_formation_settings.node.add_dependency(sagemaker_role)


        # Common blueprint parameters
        common_regional_parameters = {
            "S3Location": f"s3://{domain_bucket.bucket_name}",
            "Subnets": ",".join(subnet_ids),
            "VpcId": self.vpc.vpc_id,
        }

        # Create blueprints
        self.lakehouse_catalog = datazone.CfnEnvironmentBlueprintConfiguration(
            self, "LakehouseCatalog",
            domain_identifier=datazone_domain.attr_id,
            environment_blueprint_identifier="LakehouseCatalog",
            enabled_regions=[self.region],
            provisioning_role_arn=provisioning_role.role_arn,
            manage_access_role_arn=sagemaker_role.role_arn,
            regional_parameters=[
                datazone.CfnEnvironmentBlueprintConfiguration.RegionalParameterProperty(
                    region=self.region,
                    parameters=common_regional_parameters,
                )
            ],
        )

        self.tooling = datazone.CfnEnvironmentBlueprintConfiguration(
            self, "Tooling",
            domain_identifier=datazone_domain.attr_id,
            environment_blueprint_identifier="Tooling",
            enabled_regions=[self.region],
            provisioning_role_arn=provisioning_role.role_arn,
            manage_access_role_arn=sagemaker_role.role_arn,
            regional_parameters=[
                datazone.CfnEnvironmentBlueprintConfiguration.RegionalParameterProperty(
                    region=self.region,
                    parameters=common_regional_parameters,
                )
            ],
        )

        self.data_lake = datazone.CfnEnvironmentBlueprintConfiguration(
            self, "DataLake",
            domain_identifier=datazone_domain.attr_id,
            environment_blueprint_identifier="DataLake",
            enabled_regions=[self.region],
            provisioning_role_arn=provisioning_role.role_arn,
            manage_access_role_arn=sagemaker_role.role_arn,
            regional_parameters=[
                datazone.CfnEnvironmentBlueprintConfiguration.RegionalParameterProperty(
                    region=self.region,
                    parameters=common_regional_parameters,
                )
            ],
        )

        self.ml_experiments = datazone.CfnEnvironmentBlueprintConfiguration(
            self, "MLExperiments",
            domain_identifier=datazone_domain.attr_id,
            environment_blueprint_identifier="MLExperiments",
            enabled_regions=[self.region],
            provisioning_role_arn=provisioning_role.role_arn,
            manage_access_role_arn=sagemaker_role.role_arn,
            regional_parameters=[
                datazone.CfnEnvironmentBlueprintConfiguration.RegionalParameterProperty(
                    region=self.region,
                    parameters=common_regional_parameters,
                )
            ],
        )

        self.redshift_serverless = datazone.CfnEnvironmentBlueprintConfiguration(
            self, "RedshiftServerless",
            domain_identifier=datazone_domain.attr_id,
            environment_blueprint_identifier="RedshiftServerless",
            enabled_regions=[self.region],
            provisioning_role_arn=provisioning_role.role_arn,
            manage_access_role_arn=sagemaker_role.role_arn,
            regional_parameters=[
                datazone.CfnEnvironmentBlueprintConfiguration.RegionalParameterProperty(
                    region=self.region,
                    parameters=common_regional_parameters,
                )
            ],
        )

        self.emr_serverless = datazone.CfnEnvironmentBlueprintConfiguration(
            self, "EmrServerless",
            domain_identifier=datazone_domain.attr_id,
            environment_blueprint_identifier="EmrServerless",
            enabled_regions=[self.region],
            provisioning_role_arn=provisioning_role.role_arn,
            manage_access_role_arn=sagemaker_role.role_arn,
            regional_parameters=[
                datazone.CfnEnvironmentBlueprintConfiguration.RegionalParameterProperty(
                    region=self.region,
                    parameters=common_regional_parameters,
                )
            ],
        )

        self.workflows = datazone.CfnEnvironmentBlueprintConfiguration(
            self, "Workflows",
            domain_identifier=datazone_domain.attr_id,
            environment_blueprint_identifier="Workflows",
            enabled_regions=[self.region],
            provisioning_role_arn=provisioning_role.role_arn,
            manage_access_role_arn=sagemaker_role.role_arn,
            regional_parameters=[
                datazone.CfnEnvironmentBlueprintConfiguration.RegionalParameterProperty(
                    region=self.region,
                    parameters=common_regional_parameters,
                )
            ],
        )

        self.emr_on_ec2 = datazone.CfnEnvironmentBlueprintConfiguration(
            self, "EmrOnEc2",
            domain_identifier=datazone_domain.attr_id,
            environment_blueprint_identifier="EmrOnEc2",
            enabled_regions=[self.region],
            provisioning_role_arn=provisioning_role.role_arn,
            manage_access_role_arn=sagemaker_role.role_arn,
            regional_parameters=[
                datazone.CfnEnvironmentBlueprintConfiguration.RegionalParameterProperty(
                    region=self.region,
                    parameters=common_regional_parameters,
                )
            ],
        )

        bedrock_blueprints = [
            "AmazonBedrockGuardrail", "AmazonBedrockPrompt", "AmazonBedrockEvaluation",
            "AmazonBedrockKnowledgeBase", "AmazonBedrockChatAgent", "AmazonBedrockFunction",
            "AmazonBedrockFlow"
        ]

        self.bedrock_configs = {}
        for blueprint in bedrock_blueprints:
            self.bedrock_configs[blueprint] = datazone.CfnEnvironmentBlueprintConfiguration(
                self, blueprint,
                domain_identifier=datazone_domain.attr_id,
                environment_blueprint_identifier=blueprint,
                enabled_regions=[self.region],
                provisioning_role_arn=provisioning_role.role_arn,
                manage_access_role_arn=sagemaker_role.role_arn,
                regional_parameters=[
                    datazone.CfnEnvironmentBlueprintConfiguration.RegionalParameterProperty(
                        region=self.region,
                        parameters=common_regional_parameters,
                    )
                ],
            )

        # Create All Capabilities Project Profile
        all_capabilities_project_profile = datazone.CfnProjectProfile(
            self, "AllCapabilitiesProjectProfile",
            domain_identifier=datazone_domain.attr_id,
            domain_unit_identifier=datazone_domain.attr_root_domain_unit_id,
            name="All capabilities",
            description="Analyze data and build machine learning and generative AI models and applications",
            status="ENABLED",
            environment_configurations=[
                datazone.CfnProjectProfile.EnvironmentConfigurationProperty(
                    name="Tooling",
                    environment_blueprint_id=self.tooling.attr_environment_blueprint_id,
                    description="Core tooling and infrastructure for projects",
                    deployment_mode="ON_CREATE",
                    deployment_order=0,
                    aws_region=datazone.CfnProjectProfile.RegionProperty(region_name=self.region),
                    aws_account=datazone.CfnProjectProfile.AwsAccountProperty(aws_account_id=self.account),
                ),
                datazone.CfnProjectProfile.EnvironmentConfigurationProperty(
                    name="Lakehouse Database",
                    environment_blueprint_id=self.data_lake.attr_environment_blueprint_id,
                    description="Creates databases in Amazon SageMaker Lakehouse",
                    deployment_mode="ON_CREATE",
                    deployment_order=1,
                    aws_region=datazone.CfnProjectProfile.RegionProperty(region_name=self.region),
                    aws_account=datazone.CfnProjectProfile.AwsAccountProperty(aws_account_id=self.account),
                ),
                datazone.CfnProjectProfile.EnvironmentConfigurationProperty(
                    name="MLExperiments",
                    environment_blueprint_id=self.ml_experiments.attr_environment_blueprint_id,
                    description="Machine Learning experiments and model development",
                    deployment_mode="ON_DEMAND",
                    deployment_order=2,
                    aws_region=datazone.CfnProjectProfile.RegionProperty(region_name=self.region),
                    aws_account=datazone.CfnProjectProfile.AwsAccountProperty(aws_account_id=self.account),
                ),
                datazone.CfnProjectProfile.EnvironmentConfigurationProperty(
                    name="LakehouseCatalog",
                    environment_blueprint_id=self.lakehouse_catalog.attr_environment_blueprint_id,
                    description="Data catalog and lakehouse capabilities",
                    deployment_mode="ON_DEMAND",
                    deployment_order=3,
                    aws_region=datazone.CfnProjectProfile.RegionProperty(region_name=self.region),
                    aws_account=datazone.CfnProjectProfile.AwsAccountProperty(aws_account_id=self.account),
                ),
                datazone.CfnProjectProfile.EnvironmentConfigurationProperty(
                    name="RedshiftServerless",
                    environment_blueprint_id=self.redshift_serverless.attr_environment_blueprint_id,
                    description="Serverless data warehouse capabilities",
                    deployment_mode="ON_DEMAND",
                    deployment_order=4,
                    aws_region=datazone.CfnProjectProfile.RegionProperty(region_name=self.region),
                    aws_account=datazone.CfnProjectProfile.AwsAccountProperty(aws_account_id=self.account),
                ),
                datazone.CfnProjectProfile.EnvironmentConfigurationProperty(
                    name="Workflows",
                    environment_blueprint_id=self.workflows.attr_environment_blueprint_id,
                    description="Airflow-based workflow orchestration",
                    deployment_mode="ON_DEMAND",
                    deployment_order=5,
                    aws_region=datazone.CfnProjectProfile.RegionProperty(region_name=self.region),
                    aws_account=datazone.CfnProjectProfile.AwsAccountProperty(aws_account_id=self.account),
                ),
                datazone.CfnProjectProfile.EnvironmentConfigurationProperty(
                    name="EmrServerless",
                    environment_blueprint_id=self.emr_serverless.attr_environment_blueprint_id,
                    description="Serverless EMR for big data processing",
                    deployment_mode="ON_DEMAND",
                    deployment_order=6,
                    aws_region=datazone.CfnProjectProfile.RegionProperty(region_name=self.region),
                    aws_account=datazone.CfnProjectProfile.AwsAccountProperty(aws_account_id=self.account),
                ),
                datazone.CfnProjectProfile.EnvironmentConfigurationProperty(
                    name="EmrOnEc2",
                    environment_blueprint_id=self.emr_on_ec2.attr_environment_blueprint_id,
                    description="EMR clusters on EC2 for big data processing",
                    deployment_mode="ON_DEMAND",
                    deployment_order=7,
                    aws_region=datazone.CfnProjectProfile.RegionProperty(region_name=self.region),
                    aws_account=datazone.CfnProjectProfile.AwsAccountProperty(aws_account_id=self.account),
                ),
                datazone.CfnProjectProfile.EnvironmentConfigurationProperty(
                    name="BedrockGuardrail",
                    environment_blueprint_id=self.bedrock_configs["AmazonBedrockGuardrail"].attr_environment_blueprint_id,
                    description="Generative AI capabilities with Amazon Bedrock",
                    deployment_mode="ON_DEMAND",
                    deployment_order=8,
                    aws_region=datazone.CfnProjectProfile.RegionProperty(region_name=self.region),
                    aws_account=datazone.CfnProjectProfile.AwsAccountProperty(aws_account_id=self.account),
                ),
            ],
        )

        # Add dependencies to ensure blueprints are created before project profile
        all_blueprint_configs = [
            self.tooling, self.data_lake, self.ml_experiments, self.lakehouse_catalog,
            self.redshift_serverless, self.workflows, self.emr_serverless, self.emr_on_ec2,
        ] + list(self.bedrock_configs.values())
        for config in all_blueprint_configs:
            all_capabilities_project_profile.node.add_dependency(config)

        # Create generic policy grants for all environment blueprints
        self.blueprints = {
            "lakehouse_catalog": self.lakehouse_catalog,
            "tooling": self.tooling,
            "data_lake": self.data_lake,
            "ml_experiments": self.ml_experiments,
            "redshift_serverless": self.redshift_serverless,
            "emr_serverless": self.emr_serverless,
            "workflows": self.workflows,
            "emr_on_ec2": self.emr_on_ec2,
        }

        self._apply_policy_grants_to_all_blueprints(datazone_domain)
        
        # Outputs for main resources
        CfnOutput(
            self, "DataZoneDomainId",
            value=datazone_domain.attr_id,
            description="DataZone Domain ID (dzd_xxxxx)"
        )
        CfnOutput(
            self, "ProjectProfileId",
            value=all_capabilities_project_profile.attr_id,
            description="All Capabilities Project Profile ID"
        )
        CfnOutput(
            self, "VpcId",
            value=self.vpc.vpc_id,
            description="VPC ID for SageMaker Unified Studio"
        )
        CfnOutput(
            self, "S3BucketName",
            value=domain_bucket.bucket_name,
            description="S3 Bucket for domain artifacts"
        )
        CfnOutput(
            self, "Domain Execution Role",
            value=domain_execution_role.role_arn,
            description="Domain Execution Role"
        )
        CfnOutput(
            self, "Domain Service Role",
            value=domain_service_role.role_arn,
            description="Domain Service Role"
        )

        # Output each blueprint ID
        for name, bp_id in self.blueprint_ids.items():
            CfnOutput(
                self, f"{name.capitalize()}BlueprintId",
                value=bp_id,
                description=f"Environment Blueprint ID for {name}"
            )

        # Log all key IDs
        logger.info(f"DataZone Domain ID: {datazone_domain.attr_id}")
        logger.info(f"Project Profile ID: {all_capabilities_project_profile.attr_id}")
        logger.info(f"VPC ID: {self.vpc.vpc_id}")
        logger.info(f"S3 Bucket Name: {domain_bucket.bucket_name}")
        logger.info(f"Blueprint IDs: {self.blueprint_ids}")
        logger.info(f"Subnets used: {subnet_ids}")

    @property
    def blueprint_ids(self) -> dict:
        return {
            "lakehouse_catalog": self.lakehouse_catalog.attr_environment_blueprint_id,
            "tooling": self.tooling.attr_environment_blueprint_id,
            "data_lake": self.data_lake.attr_environment_blueprint_id,
            "redshift_serverless": self.redshift_serverless.attr_environment_blueprint_id,
            "emr_serverless": self.emr_serverless.attr_environment_blueprint_id,
            "ml_experiments": self.ml_experiments.attr_environment_blueprint_id,
            "workflows": self.workflows.attr_environment_blueprint_id,
            "emr_on_ec2": self.emr_on_ec2.attr_environment_blueprint_id,
            **{k.lower(): v.attr_environment_blueprint_id for k, v in self.bedrock_configs.items()}
        }
    
    def _get_blueprint_config_entity_id_bkp(self, datazone_domain, blueprint_name: str) -> cr.AwsCustomResource:
        """Get the actual blueprint configuration entity ID for policy grants"""
        
        return cr.AwsCustomResource(
            self, f"{blueprint_name}EntityIdLookup",
            on_create=cr.AwsSdkCall(
                service="datazone",
                action="listEnvironmentBlueprintConfigurations",
                parameters={
                    "domainIdentifier": datazone_domain.attr_id,
                    "environmentBlueprintIdentifier": blueprint_name
                },
                physical_resource_id=cr.PhysicalResourceId.of(f"{blueprint_name}-entity-lookup")
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=[
                        "datazone:ListEnvironmentBlueprintConfigurations",
                        "datazone:GetEnvironmentBlueprintConfiguration"
                    ],
                    resources=["*"]
                )
            ])
        )
    
    def _get_blueprint_config_entity_id(self, datazone_domain, blueprint_name: str) -> cr.AwsCustomResource:
        """Get the actual blueprint configuration entity ID for policy grants with response parsing"""
        
        # Create a Lambda function to handle the response parsing
        response_parser = _lambda.Function(
            self, f"{blueprint_name}ResponseParser",
            runtime=_lambda.Runtime.PYTHON_3_9,
            handler="index.handler",
            code=_lambda.Code.from_inline("""
    import json
    import boto3

    def handler(event, context):
        try:
            # Get request details
            domain_id = event['ResourceProperties']['DomainId']
            blueprint_name = event['ResourceProperties']['BlueprintName']
            
            # Create DataZone client
            client = boto3.client('datazone')
            
            # List blueprint configurations
            response = client.list_environment_blueprint_configurations(
                domainIdentifier=domain_id,
                environmentBlueprintIdentifier=blueprint_name
            )
            
            # Print response size for debugging
            response_str = json.dumps(response, default=str)
            print(f"Response size: {len(response_str)} characters")
            
            # Extract only the required information
            items = response.get('items', [])
            if items:
                blueprint_id = items[0].get('environmentBlueprintId', '')
                print(f"Found blueprint ID: {blueprint_id}")
                
                return {
                    'PhysicalResourceId': f"{blueprint_name}-config-id",
                    'Data': {
                        'BlueprintId': blueprint_id,
                        'ResponseSize': len(response_str)
                    }
                }
            else:
                raise Exception(f"No blueprint configurations found for {blueprint_name}")
                
        except Exception as e:
            print(f"Error: {str(e)}")
            raise e
            """),
            timeout=cdk.Duration.minutes(5)
        )
        
        # Grant permissions to the Lambda function
        response_parser.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "datazone:ListEnvironmentBlueprintConfigurations",
                    "datazone:GetEnvironmentBlueprintConfiguration"
                ],
                resources=["*"]
            )
        )
        
        return cr.AwsCustomResource(
            self, f"{blueprint_name}EntityIdLookup",
            on_create=cr.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": response_parser.function_name,
                    "Payload": json.dumps({
                        "ResourceProperties": {
                            "DomainId": datazone_domain.attr_id,
                            "BlueprintName": blueprint_name
                        }
                    })
                },
                physical_resource_id=cr.PhysicalResourceId.of(f"{blueprint_name}-entity-lookup")
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=["lambda:InvokeFunction"],
                    resources=[response_parser.function_arn]
                )
            ])
        )

    def _apply_policy_grants_to_all_blueprints(self, datazone_domain):
        """Create policy grants using hardcoded blueprint configuration IDs"""
        
        for blueprint_name in self.blueprints.keys():
            try:
                blueprint_config = self.blueprints[blueprint_name]
                entity_identifier = blueprint_config.attr_environment_blueprint_id
                print(f'entity_identifier {self.account}:{blueprint_config.attr_environment_blueprint_id}')

                if not entity_identifier:
                    print(f"No entity ID found for {blueprint_name}, skipping...")
                    continue
                
                # Create Environment From Blueprint Policy Grant
                datazone.CfnPolicyGrant(
                    self, f"{blueprint_name}CreateEnvironmentFromBlueprintGrant",
                    domain_identifier=datazone_domain.attr_id,
                    entity_identifier=f'{self.account}:{blueprint_config.attr_environment_blueprint_id}',
                    entity_type="ENVIRONMENT_BLUEPRINT_CONFIGURATION",
                    policy_type="CREATE_ENVIRONMENT_FROM_BLUEPRINT",
                    principal=datazone.CfnPolicyGrant.PolicyGrantPrincipalProperty(
                        project=datazone.CfnPolicyGrant.ProjectPolicyGrantPrincipalProperty(
                            project_designation="CONTRIBUTOR",
                            project_grant_filter=datazone.CfnPolicyGrant.ProjectGrantFilterProperty(
                                domain_unit_filter=datazone.CfnPolicyGrant.DomainUnitFilterForProjectProperty(
                                    domain_unit=datazone_domain.attr_root_domain_unit_id,
                                    include_child_domain_units=True
                                )
                            )
                        )
                    ),
                    #detail=datazone.CfnPolicyGrant.PolicyGrantDetailProperty(
                    #    create_environment_from_blueprint=datazone.CfnPolicyGrant.CreateEnvironmentFromBlueprintPolicyGrantDetailProperty()
                    #),
                    detail={
                        'createEnvironmentFromBlueprint': {}
                    }
                )
                
                print(f"Created policy grant for blueprint: {blueprint_name}")
                
            except Exception as e:
                print(f"Failed to create policy grant for blueprint {blueprint_name}: {e}")

    def _add_domain_owner_with_cdk_role(self, datazone_domain: datazone.CfnDomain) -> None:
        """Add domain owner by assuming CDK execution role with proper permissions."""
        logger.info("Adding domain owner using CDK execution role")
        
        add_owner_lambda = _lambda.Function(
            self, "AddDomainOwnerWithCdkRoleFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline("""
import boto3
import json

def handler(event, context):
    if event['RequestType'] == 'Delete':
        return {'Status': 'SUCCESS', 'PhysicalResourceId': 'domain-owner'}
    
    try:
        domain_id = event['ResourceProperties']['DomainId']
        entity_id = event['ResourceProperties']['EntityId']
        cdk_exec_role_arn = event['ResourceProperties']['CdkExecRoleArn']
        
        # Get current caller identity first
        sts = boto3.client('sts')
        current_caller = sts.get_caller_identity()
        current_arn = current_caller['Arn']
        
        print(f"Current caller ARN: {current_arn}")
        print(f"Assuming CDK execution role: {cdk_exec_role_arn}")
        
        # Assume the CDK execution role
        assumed_role = sts.assume_role(
            RoleArn=cdk_exec_role_arn,
            RoleSessionName='AddDomainOwners'
        )
        
        # Create DataZone client with assumed credentials
        datazone = boto3.client(
            'datazone',
            aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
            aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
            aws_session_token=assumed_role['Credentials']['SessionToken']
        )
        
        # Add entity owner using current caller ARN (not the assumed role)
        response = datazone.add_entity_owner(
            domainIdentifier=domain_id,
            entityType='DOMAIN_UNIT',
            entityIdentifier=entity_id,
            owner={
                'user': {
                    'userIdentifier': current_arn
                }
            }
        )
        
        return {
            'Status': 'SUCCESS',
            'PhysicalResourceId': 'domain-owner',
            'Data': {
                'OwnerId': response.get('ownerId', 'unknown'),
                'CallerArn': current_arn,
                'AssumedRole': cdk_exec_role_arn
            }
        }
        
    except Exception as e:
        print(f"Error adding domain owner: {str(e)}")
        return {
            'Status': 'FAILED',
            'Reason': str(e),
            'PhysicalResourceId': 'domain-owner'
        }
            """),
            timeout=cdk.Duration.minutes(5),
            initial_policy=[
                iam.PolicyStatement(
                    actions=[
                        "sts:GetCallerIdentity",
                        "sts:AssumeRole"
                    ],
                    resources=["*"]
                )
            ]
        )
        
        # Create custom resource
        add_owner_resource = cdk.CustomResource(
            self, "AddDomainOwnerWithCdkRoleResource",
            service_token=add_owner_lambda.function_arn,
            properties={
                "DomainId": datazone_domain.attr_id,
                "EntityId": datazone_domain.attr_root_domain_unit_id,
                "CdkExecRoleArn": f"arn:aws:iam::{self.account}:role/cdk-hnb659fds-cfn-exec-role-{self.account}-{self.region}"
            }
        )
        
        add_owner_resource.node.add_dependency(datazone_domain)
        logger.info("Created custom resource to add domain owner using CDK execution role")