# AssumeRole with hadoop-aws 2.9.1

This package provides a port of the `org.apache.hadoop.fs.s3a.auth.AssumedRoleCredentialProvider` from the
`hadoop-aws` 3.1.2 branch.

https://github.com/apache/hadoop/blob/rel/release-3.1.2/hadoop-tools/hadoop-aws/src/main/java/org/apache/hadoop/fs/s3a/auth/AssumedRoleCredentialProvider.java

hadoop-aws 3.1 has support for role assumption as described in the following documentation

https://hadoop.apache.org/docs/r3.1.0/hadoop-aws/tools/hadoop-aws/assumed_roles.html

However, for earlier version, developers could only use the TemporaryAWSCredentialProvider.

## Usage

Typical usage involves setting the hadoop properties as described in the 3.1 documentation.
For use in spark configuration, you will need to prefix the properties below with `spark.hadoop`.

```properties
fs.s3a.aws.credentials.provider = sparkhacks.AssumedRoleCredentialProviderForHadoop291
fs.s3a.assumed.role.arn = <my-target-role-arn>
fs.s3a.assumed.role.credentials.provider = com.amazonaws.auth.InstanceProfileCredentialsProvider
fs.s3a.assumed.role.session.name = my-spark-cluster
fs.s3a.assumed.role.session.duration = 1h
```

 You will also need to add this jar to your spark classpath. One way is through the `spark.jars` property. For example,

```properties
spark.jars = path/to/assumerole-hadoop291-1.0-SNAPSHOT.jar
```
