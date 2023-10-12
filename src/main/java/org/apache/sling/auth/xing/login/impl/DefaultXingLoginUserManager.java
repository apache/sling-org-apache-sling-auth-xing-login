/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.auth.xing.login.impl;

import javax.jcr.Credentials;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.jcr.ValueFactory;

import org.apache.commons.lang.StringUtils;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.auth.xing.api.AbstractXingUserManager;
import org.apache.sling.auth.xing.api.XingUser;
import org.apache.sling.auth.xing.login.XingLogin;
import org.apache.sling.auth.xing.login.XingLoginUserManager;
import org.apache.sling.auth.xing.login.XingLoginUtil;
import org.apache.sling.jcr.api.SlingRepository;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.propertytypes.ServiceDescription;
import org.osgi.service.component.propertytypes.ServiceRanking;
import org.osgi.service.component.propertytypes.ServiceVendor;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
@ServiceRanking(0)
@ServiceVendor(XingLogin.SERVICE_VENDOR)
@ServiceDescription("Default User Manager for Sling Authentication XING Login")
@Designate(ocd = DefaultXingLoginUserManager.Config.class)
public class DefaultXingLoginUserManager extends AbstractXingUserManager implements XingLoginUserManager {

    private String secretKey;

    private String userDataProperty;

    private String userHashProperty;

    @Reference
    private SlingRepository slingRepository;

    private static final String DEFAULT_USER_DATA_PROPERTY = "data";

    private static final String DEFAULT_USER_HASH_PROPERTY = "hash";

    @SuppressWarnings("java:S100")
    @ObjectClassDefinition(name = "Apache Sling Authentication XING Login “Default User Manager”",
            description = "Default User Manager for Sling Authentication XING Login")
    public @interface Config {

        @AttributeDefinition
        String org_apache_sling_auth_xing_login_impl_DefaultXingLoginUserManager_secretKey() default "";

        @AttributeDefinition
        String org_apache_sling_auth_xing_login_impl_DefaultXingLoginUserManager_user_property_data() default DEFAULT_USER_DATA_PROPERTY;

        @AttributeDefinition
        String org_apache_sling_auth_xing_login_impl_DefaultXingLoginUserManager_user_property_hash() default DEFAULT_USER_HASH_PROPERTY;

        @AttributeDefinition
        boolean org_apache_sling_auth_xing_login_impl_DefaultXingLoginUserManager_user_create_auto() default DEFAULT_AUTO_CREATE_USER;

        @AttributeDefinition
        boolean org_apache_sling_auth_xing_login_impl_DefaultXingLoginUserManager_user_update_auto() default DEFAULT_AUTO_UPDATE_USER;
    }

    private final Logger logger = LoggerFactory.getLogger(DefaultXingLoginUserManager.class);

    public DefaultXingLoginUserManager() {
    }

    @Activate
    protected void activate(final Config config) {
        logger.debug("activate");
        configure(config);
    }

    @Modified
    protected void modified(final Config config) {
        logger.debug("modified");
        configure(config);
    }

    @Deactivate
    protected void deactivate(final Config config) {
        logger.debug("deactivate");
        if (session != null) {
            session.logout();
            session = null;
        }
    }

    protected synchronized void configure(final Config config) {
        secretKey = config.org_apache_sling_auth_xing_login_impl_DefaultXingLoginUserManager_secretKey().trim();
        userDataProperty = config.org_apache_sling_auth_xing_login_impl_DefaultXingLoginUserManager_user_property_data().trim();
        userHashProperty = config.org_apache_sling_auth_xing_login_impl_DefaultXingLoginUserManager_user_property_hash().trim();
        autoCreateUser = config.org_apache_sling_auth_xing_login_impl_DefaultXingLoginUserManager_user_create_auto();
        autoUpdateUser = config.org_apache_sling_auth_xing_login_impl_DefaultXingLoginUserManager_user_update_auto();

        if (StringUtils.isEmpty(secretKey)) {
            logger.warn("configured secret key is empty");
        }
    }

    @Override
    protected SlingRepository getSlingRepository() {
        return slingRepository;
    }

    @Override
    public User createUser(final Credentials credentials) {
        logger.debug("create user");
        return storeUser(credentials);
    }

    @Override
    public User updateUser(Credentials credentials) {
        logger.debug("update user");
        return storeUser(credentials);
    }

    protected User storeUser(Credentials credentials) {
        final String givenHash = XingLoginUtil.getHash(credentials);
        final String json = XingLoginUtil.getUser(credentials);

        if (givenHash == null || json == null) {
            logger.debug("unable to get hash and/or user data from given credentials");
            return null;
        }

        // validate user data with hash
        try {
            final String computedHash = XingLoginUtil.hash(json, secretKey, XingLogin.HASH_ALGORITHM);
            final boolean match = givenHash.equals(computedHash);
            if (!match) {
                logger.warn("invalid hash or user data given, aborting");
                return null;
            }
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return null;
        }

        try {
            final XingUser xingUser = XingLoginUtil.fromJson(json);
            final String userId = xingUser.getId(); // TODO make configurable

            User user = getUser(userId);
            if (user == null) {
                logger.debug("creating a new user with id '{}'", userId);
                final Session session = getSession();
                final UserManager userManager = getUserManager(session);
                user = userManager.createUser(userId, null);
            } else {
                logger.debug("updating an existing user with id '{}'", userId);
            }

            // TODO disable user on create?
            final ValueFactory valueFactory = getSession().getValueFactory();
            final Value dataValue = valueFactory.createValue(json);
            final Value hashValue = valueFactory.createValue(givenHash);
            user.setProperty(userDataProperty, dataValue);
            user.setProperty(userHashProperty, hashValue);
            session.save();
            return user;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return null;
        }
    }

    @Override
    public String getHash(final User user) {
        try {
            final Value[] values = user.getProperty(userHashProperty);
            if (values != null && values.length == 1) {
                final Value value = values[0];
                return value.getString();
            }
        } catch (RepositoryException e) {
            logger.error(e.getMessage(), e);
        }
        return null;
    }

}
