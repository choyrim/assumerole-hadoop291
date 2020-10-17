/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sparkhacks;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.services.securitytoken.model.AWSSecurityTokenServiceException;
import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.AWSCredentialProviderList;
import org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

import static org.apache.hadoop.fs.s3a.Constants.AWS_CREDENTIALS_PROVIDER;

/**
 * Support IAM Assumed roles by instantiating an instance of
 * {@code STSAssumeRoleSessionCredentialsProvider} from configuration
 * properties, including wiring up the inner authenticator, and,
 * unless overridden, creating a session name from the current user.
 *
 * Classname is used in configuration files; do not move.
 */
public class AssumedRoleCredentialProviderForHadoop291 implements AWSCredentialsProvider,
        Closeable {

    // ---------- hacks begin ----------

    /**
     * AWS Role to request.
     */
    public static final String ASSUMED_ROLE_ARN =
            "fs.s3a.assumed.role.arn";
    /** list of providers to authenticate for the assumed role. */
    public static final String ASSUMED_ROLE_CREDENTIALS_PROVIDER =
            "fs.s3a.assumed.role.credentials.provider";
    /**
     * Session name for the assumed role, must be valid characters according
     * to the AWS APIs.
     * If not set, one is generated from the current Hadoop/Kerberos username.
     */
    public static final String ASSUMED_ROLE_SESSION_NAME =
            "fs.s3a.assumed.role.session.name";
    /**
     * Duration of assumed roles before a refresh is attempted.
     */
    public static final String ASSUMED_ROLE_SESSION_DURATION =
            "fs.s3a.assumed.role.session.duration";
    public static final long ASSUMED_ROLE_SESSION_DURATION_DEFAULT = 30 * 60;
    /** JSON policy containing the policy to apply to the role. */
    public static final String ASSUMED_ROLE_POLICY =
            "fs.s3a.assumed.role.policy";
    /** Simple Token Service Endpoint. If unset, uses the default endpoint. */
    public static final String ASSUMED_ROLE_STS_ENDPOINT =
            "fs.s3a.assumed.role.sts.endpoint";
    /**
     * Load list of AWS credential provider/credential provider factory classes.
     * @param conf configuration
     * @param key key
     * @param defaultValue list of default values
     * @return the list of classes, possibly empty
     * @throws IOException on a failure to load the list.
     */
    public static Class<?>[] loadAWSProviderClasses(Configuration conf,
                                                    String key,
                                                    Class<?>... defaultValue) throws IOException {
        try {
            return conf.getClasses(key, defaultValue);
        } catch (RuntimeException e) {
            Throwable c = e.getCause() != null ? e.getCause() : e;
            throw new IOException("From option " + key + ' ' + c, c);
        }
    }
    static final String NOT_AWS_PROVIDER =
            "does not implement AWSCredentialsProvider";
    static final String ABSTRACT_PROVIDER =
            "is abstract and therefore cannot be created";
    static final String CONSTRUCTOR_EXCEPTION = "constructor exception";
    static final String INSTANTIATION_EXCEPTION
            = "instantiation exception";
    /**
     * Returns the public constructor of {@code cl} specified by the list of
     * {@code args} or {@code null} if {@code cl} has no public constructor that
     * matches that specification.
     * @param cl class
     * @param args constructor argument types
     * @return constructor or null
     */
    private static Constructor<?> getConstructor(Class<?> cl, Class<?>... args) {
        try {
            Constructor cons = cl.getDeclaredConstructor(args);
            return Modifier.isPublic(cons.getModifiers()) ? cons : null;
        } catch (NoSuchMethodException | SecurityException e) {
            return null;
        }
    }
    /**
     * Returns the public static method of {@code cl} that accepts no arguments
     * and returns {@code returnType} specified by {@code methodName} or
     * {@code null} if {@code cl} has no public static method that matches that
     * specification.
     * @param cl class
     * @param returnType return type
     * @param methodName method name
     * @return method or null
     */
    private static Method getFactoryMethod(Class<?> cl, Class<?> returnType,
                                           String methodName) {
        try {
            Method m = cl.getDeclaredMethod(methodName);
            if (Modifier.isPublic(m.getModifiers()) &&
                    Modifier.isStatic(m.getModifiers()) &&
                    returnType.isAssignableFrom(m.getReturnType())) {
                return m;
            } else {
                return null;
            }
        } catch (NoSuchMethodException | SecurityException e) {
            return null;
        }
    }
    /**
     * Create an AWS credential provider from its class by using reflection.  The
     * class must implement one of the following means of construction, which are
     * attempted in order:
     *
     * <ol>
     * <li>a public constructor accepting
     *    org.apache.hadoop.conf.Configuration</li>
     * <li>a public static method named getInstance that accepts no
     *    arguments and returns an instance of
     *    com.amazonaws.auth.AWSCredentialsProvider, or</li>
     * <li>a public default constructor.</li>
     * </ol>
     *
     * @param conf configuration
     * @param credClass credential class
     * @return the instantiated class
     * @throws IOException on any instantiation failure.
     */
    static AWSCredentialsProvider createAWSCredentialProvider(
            Configuration conf, Class<?> credClass) throws IOException {
        AWSCredentialsProvider credentials = null;
        String className = credClass.getName();
        if (!AWSCredentialsProvider.class.isAssignableFrom(credClass)) {
            throw new IOException("Class " + credClass + " " + NOT_AWS_PROVIDER);
        }
        if (Modifier.isAbstract(credClass.getModifiers())) {
            throw new IOException("Class " + credClass + " " + ABSTRACT_PROVIDER);
        }
        LOG.debug("Credential provider class is {}", className);

        try {
            // new X(conf)
            Constructor cons = getConstructor(credClass, Configuration.class);
            if (cons != null) {
                credentials = (AWSCredentialsProvider)cons.newInstance(conf);
                return credentials;
            }

            // X.getInstance()
            Method factory = getFactoryMethod(credClass, AWSCredentialsProvider.class,
                    "getInstance");
            if (factory != null) {
                credentials = (AWSCredentialsProvider)factory.invoke(null);
                return credentials;
            }

            // new X()
            cons = getConstructor(credClass);
            if (cons != null) {
                credentials = (AWSCredentialsProvider)cons.newInstance();
                return credentials;
            }

            // no supported constructor or factory method found
            throw new IOException(String.format("%s " + CONSTRUCTOR_EXCEPTION
                    + ".  A class specified in %s must provide a public constructor "
                    + "accepting Configuration, or a public factory method named "
                    + "getInstance that accepts no arguments, or a public default "
                    + "constructor.", className, AWS_CREDENTIALS_PROVIDER));
        } catch (ReflectiveOperationException | IllegalArgumentException e) {
            // supported constructor or factory method found, but the call failed
            throw new IOException(className + " " + INSTANTIATION_EXCEPTION +".", e);
        }
    }

    // ---------- hacks end ----------

    private static final Logger LOG =
            LoggerFactory.getLogger(AssumedRoleCredentialProviderForHadoop291.class);
    public static final String NAME
            = "org.apache.hadoop.fs.s3a.AssumedRoleCredentialProvider";

    static final String E_FORBIDDEN_PROVIDER =
            "AssumedRoleCredentialProvider cannot be in "
                    + ASSUMED_ROLE_CREDENTIALS_PROVIDER;

    public static final String E_NO_ROLE = "Unset property "
            + ASSUMED_ROLE_ARN;

    private final STSAssumeRoleSessionCredentialsProvider stsProvider;

    private final String sessionName;

    private final long duration;

    private final String arn;


    /**
     * Instantiate.
     * This calls {@link #getCredentials()} to fail fast on the inner
     * role credential retrieval.
     * @param conf configuration
     * @throws IOException on IO problems and some parameter checking
     * @throws IllegalArgumentException invalid parameters
     * @throws AWSSecurityTokenServiceException problems getting credentials
     */
    public AssumedRoleCredentialProviderForHadoop291(Configuration conf)
            throws IOException {

        arn = conf.getTrimmed(ASSUMED_ROLE_ARN, "");
        if (StringUtils.isEmpty(arn)) {
            throw new IOException(E_NO_ROLE);
        }

        // build up the base provider
        Class<?>[] awsClasses = loadAWSProviderClasses(conf,
                ASSUMED_ROLE_CREDENTIALS_PROVIDER,
                SimpleAWSCredentialsProvider.class);
        AWSCredentialProviderList credentials = new AWSCredentialProviderList();
        for (Class<?> aClass : awsClasses) {
            if (this.getClass().equals(aClass)) {
                throw new IOException(E_FORBIDDEN_PROVIDER);
            }
            credentials.add(createAWSCredentialProvider(conf, aClass));
        }

        // then the STS binding
        sessionName = conf.getTrimmed(ASSUMED_ROLE_SESSION_NAME,
                buildSessionName());
        duration = conf.getTimeDuration(ASSUMED_ROLE_SESSION_DURATION,
                ASSUMED_ROLE_SESSION_DURATION_DEFAULT, TimeUnit.SECONDS);
        String policy = conf.getTrimmed(ASSUMED_ROLE_POLICY, "");

        LOG.debug("{}", this);
        STSAssumeRoleSessionCredentialsProvider.Builder builder
                = new STSAssumeRoleSessionCredentialsProvider.Builder(arn, sessionName);
        builder.withRoleSessionDurationSeconds((int) duration);
        if (StringUtils.isNotEmpty(policy)) {
            LOG.debug("Scope down policy {}", policy);
            builder.withScopeDownPolicy(policy);
        }
        String epr = conf.get(ASSUMED_ROLE_STS_ENDPOINT, "");
        if (StringUtils.isNotEmpty(epr)) {
            LOG.debug("STS Endpoint: {}", epr);
            builder.withServiceEndpoint(epr);
        }
        LOG.debug("Credentials to obtain role credentials: {}", credentials);
        builder.withLongLivedCredentialsProvider(credentials);
        stsProvider = builder.build();
        // and force in a fail-fast check just to keep the stack traces less
        // convoluted
        getCredentials();
    }

    /**
     * Get credentials.
     * @return the credentials
     * @throws AWSSecurityTokenServiceException if none could be obtained.
     */
    @Override
    public AWSCredentials getCredentials() {
        try {
            return stsProvider.getCredentials();
        } catch (AWSSecurityTokenServiceException e) {
            LOG.error("Failed to get credentials for role {}",
                    arn, e);
            throw e;
        }
    }

    @Override
    public void refresh() {
        stsProvider.refresh();
    }

    /**
     * Propagate the close() call to the inner stsProvider.
     */
    @Override
    public void close() {
        stsProvider.close();
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder(
                "AssumedRoleCredentialProvider{");
        sb.append("role='").append(arn).append('\'');
        sb.append(", session'").append(sessionName).append('\'');
        sb.append(", duration=").append(duration);
        sb.append('}');
        return sb.toString();
    }

    /**
     * Build the session name from the current user's shortname.
     * @return a string for the session name.
     * @throws IOException failure to get the current user
     */
    static String buildSessionName() throws IOException {
        return sanitize(UserGroupInformation.getCurrentUser()
                .getShortUserName());
    }

    /**
     * Build a session name from the string, sanitizing it for the permitted
     * characters.
     * @param session source session
     * @return a string for use in role requests.
     */
    @VisibleForTesting
    static String sanitize(String session) {
        StringBuilder r = new StringBuilder(session.length());
        for (char c: session.toCharArray()) {
            if ("abcdefghijklmnopqrstuvwxyz0123456789,.@-".contains(
                    Character.toString(c).toLowerCase(Locale.ENGLISH))) {
                r.append(c);
            } else {
                r.append('-');
            }
        }
        return r.toString();
    }

}