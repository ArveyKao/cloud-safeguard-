// The RAM setup a supervisor does once per cloud account. docs/QUICKSTART.md
// Part 2 shows the same names and policies; a Go test keeps the action list
// in step with the access templates.

/** The RAM role Cloud Safeguard assumes. */
export const ROLE_NAME = 'cloud-safeguard'
/** The RAM user whose AccessKey Cloud Safeguard stores. */
export const BROKER_USER = 'cloud-safeguard-broker'

export const roleArn = (accountId: string) => `acs:ram::${accountId}:role/${ROLE_NAME}`

/**
 * Everything the access templates can ask for, and nothing else. No wildcard
 * per service: ecs:* would include ecs:ModifyInstanceAttribute, which can set
 * an instance's login password.
 */
export const ROLE_ACTIONS = [
  'ecs:Describe*', 'ecs:StartInstance', 'ecs:StopInstance', 'ecs:RebootInstance',
  'ecs:RunInstances', 'ecs:CreateInstance', 'ecs:DeleteInstance',
  'alidns:Describe*', 'alidns:AddDomainRecord', 'alidns:UpdateDomainRecord',
  'alidns:DeleteDomainRecord', 'alidns:SetDomainRecordStatus', 'alidns:AddDomain', 'alidns:DeleteDomain',
  'oss:Get*', 'oss:List*', 'oss:PutObject', 'oss:DeleteObject', 'oss:AbortMultipartUpload',
  'oss:PutBucket', 'oss:DeleteBucket',
  'sts:GetCallerIdentity',
]

const json = (v: unknown) => JSON.stringify(v, null, 2)

/** Attached to the broker user: its only permission. */
export const brokerPolicy = (accountId: string) => json({
  Version: '1',
  Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: roleArn(accountId) }],
})

/** The role's trust policy: only the broker user may assume it. */
export const trustPolicy = (accountId: string) => json({
  Version: '1',
  Statement: [{
    Effect: 'Allow', Action: 'sts:AssumeRole',
    Principal: { RAM: [`acs:ram::${accountId}:user/${BROKER_USER}`] },
  }],
})

/** Attached to the role: the outer limit of every credential. */
export const rolePermissions = () => json({
  Version: '1',
  Statement: [
    { Effect: 'Allow', Action: ROLE_ACTIONS, Resource: '*' },
    { Effect: 'Deny', Action: ['ram:*', 'sts:AssumeRole'], Resource: '*' },
  ],
})

// ---- AWS (CONTRACT §17.13): an IAM user that may only assume one role ----

export const awsRoleArn = (accountId: string) => `arn:aws:iam::${accountId}:role/${ROLE_NAME}`

/** Everything the AWS access templates can ask for, and nothing else. */
export const AWS_ROLE_ACTIONS = [
  's3:Get*', 's3:List*', 's3:PutObject', 's3:DeleteObject', 's3:AbortMultipartUpload',
  's3:CreateBucket', 's3:DeleteBucket',
  'sts:GetCallerIdentity',
]

/** Attached to the IAM user: its only permission. */
export const awsBrokerPolicy = (accountId: string) => json({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: awsRoleArn(accountId) }],
})

/** The role's trust policy: only the IAM user may assume it. */
export const awsTrustPolicy = (accountId: string) => json({
  Version: '2012-10-17',
  Statement: [{
    Effect: 'Allow', Action: 'sts:AssumeRole',
    Principal: { AWS: `arn:aws:iam::${accountId}:user/${BROKER_USER}` },
  }],
})

/** Attached to the role: the outer limit of every credential. */
export const awsRolePermissions = () => json({
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: AWS_ROLE_ACTIONS, Resource: '*' },
    { Effect: 'Deny', Action: ['iam:*', 'organizations:*', 'sts:AssumeRole'], Resource: '*' },
  ],
})
