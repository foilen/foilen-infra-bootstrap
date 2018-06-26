/*
    Foilen Infra Bootstrap
    https://github.com/foilen/foilen-infra-bootstrap
    Copyright (c) 2017-2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.bootstrap;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.client.HttpClientErrorException;

import com.foilen.infra.api.InfraApiService;
import com.foilen.infra.api.InfraApiServiceImpl;
import com.foilen.infra.api.request.ChangesRequest;
import com.foilen.infra.api.request.LinkDetails;
import com.foilen.infra.api.request.ResourceDetails;
import com.foilen.infra.api.response.ResponseWithStatus;
import com.foilen.infra.plugin.core.system.common.service.IPPluginServiceImpl;
import com.foilen.infra.plugin.core.system.fake.CommonServicesContextBean;
import com.foilen.infra.plugin.core.system.fake.InitSystemBean;
import com.foilen.infra.plugin.core.system.fake.InternalServicesContextBean;
import com.foilen.infra.plugin.system.utils.DockerUtils;
import com.foilen.infra.plugin.system.utils.UnixUsersAndGroupsUtils;
import com.foilen.infra.plugin.system.utils.impl.DockerUtilsImpl;
import com.foilen.infra.plugin.system.utils.impl.UnixUsersAndGroupsUtilsImpl;
import com.foilen.infra.plugin.system.utils.model.ApplicationBuildDetails;
import com.foilen.infra.plugin.system.utils.model.ContainersManageContext;
import com.foilen.infra.plugin.system.utils.model.DockerState;
import com.foilen.infra.plugin.v1.core.context.ChangesContext;
import com.foilen.infra.plugin.v1.core.service.IPResourceService;
import com.foilen.infra.plugin.v1.core.service.internal.InternalChangeService;
import com.foilen.infra.plugin.v1.model.infra.InfraLoginConfig;
import com.foilen.infra.plugin.v1.model.infra.InfraUiConfig;
import com.foilen.infra.plugin.v1.model.outputter.docker.DockerContainerOutputContext;
import com.foilen.infra.plugin.v1.model.resource.LinkTypeConstants;
import com.foilen.infra.resource.application.Application;
import com.foilen.infra.resource.dns.DnsEntry;
import com.foilen.infra.resource.dns.model.DnsEntryType;
import com.foilen.infra.resource.infraconfig.InfraConfig;
import com.foilen.infra.resource.machine.Machine;
import com.foilen.infra.resource.mariadb.MariaDBDatabase;
import com.foilen.infra.resource.mariadb.MariaDBServer;
import com.foilen.infra.resource.mariadb.MariaDBUser;
import com.foilen.infra.resource.unixuser.UnixUser;
import com.foilen.infra.resource.unixuser.helper.UnixUserAvailableIdHelper;
import com.foilen.smalltools.JavaEnvironmentValues;
import com.foilen.smalltools.tools.DateTools;
import com.foilen.smalltools.tools.InternetTools;
import com.foilen.smalltools.tools.JsonTools;
import com.foilen.smalltools.tools.LogbackTools;
import com.foilen.smalltools.tools.SecureRandomTools;
import com.foilen.smalltools.tools.SystemTools;
import com.foilen.smalltools.tools.ThreadTools;
import com.foilen.smalltools.tuple.Tuple2;
import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.io.Files;
import com.mysql.jdbc.jdbc2.optional.MysqlConnectionPoolDataSource;

public class InfraBootstrapApp {

    private static final String INSERT_API_USER = "INSERT INTO api_user(is_admin, created_on, description, expire_on, user_id, user_hashed_key, version) VALUES(?, ?, ?, ?, ?, ?, 0)";
    private static final String INSERT_USER = "INSERT INTO user(is_admin, user_id, version) VALUES(?, ?, 0)";

    private static final String INSERT_API_MACHINE_USER = "INSERT INTO api_machine_user(id, machine_name, user_key) VALUES(?, ?, ?)";

    private static BufferedReader br;

    static private boolean allDefaults = false;

    private static void applyState(IPResourceService resourceService, DockerState dockerState) {

        // Install unix users
        System.out.println("\n---[ Install unix users ]---");
        UnixUsersAndGroupsUtils unixUsersAndGroupsUtils = new UnixUsersAndGroupsUtilsImpl();
        for (UnixUser unixUser : resourceService.resourceFindAll(resourceService.createResourceQuery(UnixUser.class))) {
            System.out.println("\t" + unixUser.getName() + " (" + unixUser.getId() + ")");
            unixUsersAndGroupsUtils.userCreate(unixUser.getName(), unixUser.getId(), unixUser.getHomeFolder(), null, null);
        }

        // Get the fake DNS information
        System.out.println("\n---[ Get the needed DNS entries (for Fake DNS Mode) ]---");
        List<DnsEntryType> supportedDnsType = Arrays.asList(DnsEntryType.A, DnsEntryType.AAAA, DnsEntryType.CNAME);
        List<String> fakeDnsHostsEntries = new ArrayList<>();
        for (DnsEntry dnsEntry : resourceService.resourceFindAll(resourceService.createResourceQuery(DnsEntry.class))) {
            if (supportedDnsType.contains(dnsEntry.getType())) {
                System.out.println("\t" + dnsEntry.getName() + " / " + dnsEntry.getType() + " (SET)");
                fakeDnsHostsEntries.add("172.20.0.1 " + dnsEntry.getName() + " #FakeDNS");
            } else {
                System.out.println("\t" + dnsEntry.getName() + " / " + dnsEntry.getType() + " (SKIPPED)");
            }
        }
        System.out.println("\n\tEntries for the /etc/hosts file:");
        List<String> finalFakeDnsHostsEntries = fakeDnsHostsEntries.stream() //
                .sorted() //
                .distinct() //
                .collect(Collectors.toList());
        finalFakeDnsHostsEntries.forEach(it -> {
            System.out.println("\t\t" + it);
        });

        // Install applications (docker)
        DockerUtils dockerUtils = new DockerUtilsImpl();
        File tmpDirectory = Files.createTempDir();
        System.out.println("\n---[ Install application (docker) ]---");
        List<Application> applications = resourceService.resourceFindAll(resourceService.createResourceQuery(Application.class));
        ContainersManageContext containersManageContext = new ContainersManageContext();
        applications.stream().forEach(application -> {
            String applicationName = application.getName();
            String buildDirectory = tmpDirectory.getAbsolutePath() + "/" + applicationName + "/";

            // Add the fake dns
            application.getApplicationDefinition().addCopyWhenStartedContent("/tmp/fakedns.txt", Joiner.on('\n').join(finalFakeDnsHostsEntries));
            application.getApplicationDefinition().addExecuteWhenStartedCommand("cat /tmp/fakedns.txt >> /etc/hosts");

            // Add to the container context
            DockerContainerOutputContext outputContext = new DockerContainerOutputContext(applicationName, applicationName, applicationName, buildDirectory);
            ApplicationBuildDetails applicationBuildDetails = new ApplicationBuildDetails();
            applicationBuildDetails.setApplicationDefinition(application.getApplicationDefinition());
            applicationBuildDetails.setOutputContext(outputContext);
            containersManageContext.getAlwaysRunningApplications().add(applicationBuildDetails);
        });
        containersManageContext.setDockerState(dockerState);
        dockerUtils.containersManage(containersManageContext);

        for (String containerName : dockerState.getRunningContainersByName().keySet()) {
            System.out.println("\t" + containerName + " [STARTED] (" + dockerState.getIpByName().get(containerName) + ")");
        }
        if (!dockerState.getFailedContainersByName().isEmpty()) {
            for (String containerName : dockerState.getFailedContainersByName().keySet()) {
                System.out.println("\t" + containerName + " [FAILED]");
            }
            throw new InfraBootstrapException("Got Docker failures");
        }

    }

    private static JdbcTemplate getJdbcTemplate(String serverName, int port, String databaseName, String databaseUserName, String databaseUserPassword) {
        MysqlConnectionPoolDataSource dataSource = new MysqlConnectionPoolDataSource();
        dataSource.setServerName(serverName);
        dataSource.setPort(port);
        dataSource.setDatabaseName(databaseName);
        dataSource.setUser(databaseUserName);
        dataSource.setPassword(databaseUserPassword);
        return new JdbcTemplate(dataSource);
    }

    private static String getLine() {
        try {
            return br.readLine();
        } catch (IOException e) {
            throw new InfraBootstrapException(e);
        }
    }

    private static String getText(String prompt, String defaultValue) {

        System.out.print(prompt + " [" + defaultValue + "] ");
        if (allDefaults) {
            System.out.println();
            return defaultValue;
        }

        String input = getLine();
        if (Strings.isNullOrEmpty(input)) {
            return defaultValue;
        }

        return input;
    }

    public static void main(String[] args) {

        if (br == null) {
            br = new BufferedReader(new InputStreamReader(System.in));
        }

        List<String> arguments = new ArrayList<>(Arrays.asList(args));

        // Check the login mode
        boolean isDebug = false;
        boolean isInfo = false;
        if (arguments.remove("--debug")) {
            isDebug = true;
        }
        if (arguments.remove("--info")) {
            isInfo = true;
        }

        if (isDebug) {
            LogbackTools.changeConfig("/logback-debug.xml");
        } else if (isInfo) {
            LogbackTools.changeConfig("/logback-info.xml");
        } else {
            LogbackTools.changeConfig("/logback-quiet.xml");
        }

        // Check if automatically getting the defaults
        if (arguments.remove("--allDefaults")) {
            allDefaults = true;
        }

        // Prepare config
        InfraUiConfig infraUiConfig = new InfraUiConfig();
        infraUiConfig.setMailFrom(getText("[COMMON] Email address that sends information and alerts (mail from)", "infra-ui@localhost").toLowerCase());
        infraUiConfig.setMailAlertsTo(getText("[COMMON] Email address where to send alerts", "admin@localhost").toLowerCase());
        infraUiConfig.setMailHost("127.0.0.1");
        infraUiConfig.setMailPort(25);

        infraUiConfig.setCsrfSalt(SecureRandomTools.randomHexString(25));

        infraUiConfig.setBaseUrl(getText("[UI] Base URL", "http://infra.localhost").toLowerCase());
        // TODO Support HTTPS

        infraUiConfig.setMysqlDatabaseName(getText("[UI] MySQL Database Name", "infra_ui").toLowerCase());
        infraUiConfig.setMysqlDatabaseUserName(getText("[UI] MySQL Database User Name", "infra_ui").toLowerCase());
        infraUiConfig.setMysqlDatabasePassword(getText("[UI] MySQL Database User Password", SecureRandomTools.randomHexString(25)).toLowerCase());
        infraUiConfig.setLoginCookieSignatureSalt(SecureRandomTools.randomHexString(25));

        infraUiConfig.getLoginConfigDetails().setAppId(SecureRandomTools.randomHexString(10));
        infraUiConfig.getLoginConfigDetails().setBaseUrl(getText("[LOGIN] Base URL", "http://login.localhost").toLowerCase());
        InfraLoginConfig loginConfig = new InfraLoginConfig();
        loginConfig.setAdministratorEmail(infraUiConfig.getMailAlertsTo());
        loginConfig.setApplicationId(infraUiConfig.getLoginConfigDetails().getAppId());
        loginConfig.setCookieDateName((getText("[LOGIN] Cookie Date Name", "l_date").toLowerCase()));
        loginConfig.setCookieSignatureName(getText("[LOGIN] Cookie Signature Name", "l_sign").toLowerCase());
        loginConfig.setCookieSignatureSalt(SecureRandomTools.randomHexString(25));
        loginConfig.setCookieUserName(getText("[LOGIN] Cookie Username Name", "l_username").toLowerCase());
        loginConfig.setCsrfSalt(SecureRandomTools.randomHexString(25));
        loginConfig.setFromEmail(infraUiConfig.getMailFrom());
        loginConfig.setLoginBaseUrl(infraUiConfig.getLoginConfigDetails().getBaseUrl());
        loginConfig.setMysqlDatabaseName(getText("[LOGIN] MySQL Database Name", "infra_login").toLowerCase());
        loginConfig.setMysqlHostName("127.0.0.1");
        loginConfig.setMysqlDatabaseUserName(getText("[LOGIN] MySQL Database User Name", "infra_login").toLowerCase());
        loginConfig.setMysqlDatabasePassword(getText("[LOGIN] MySQL Database User Password", SecureRandomTools.randomHexString(25)).toLowerCase());

        System.out.println("\nReview the config:");
        System.out.println("---[ Login ]---");
        System.out.println(JsonTools.prettyPrint(loginConfig));
        System.out.println("---[ UI ]---");
        System.out.println(JsonTools.prettyPrint(infraUiConfig));
        System.out.println("Press a key to continue...");
        getLine();

        // Prepare the system
        AnnotationConfigApplicationContext applicationContext = new AnnotationConfigApplicationContext();
        applicationContext.register(InfraBootstrapSpringConfig.class);
        applicationContext.register(CommonServicesContextBean.class);
        applicationContext.register(InitSystemBean.class);
        applicationContext.register(InternalServicesContextBean.class);
        applicationContext.register(IPPluginServiceImpl.class);
        applicationContext.scan("com.foilen.infra.plugin.core.system.fake.service");
        applicationContext.refresh();

        IPResourceService resourceService = applicationContext.getBean(IPResourceService.class);
        InternalChangeService internalChangeService = applicationContext.getBean(InternalChangeService.class);
        DockerState dockerState = new DockerState();

        ChangesContext changes = new ChangesContext(resourceService);

        // Create machine
        String machineName = SystemTools.getPropertyOrEnvironment("MACHINE_HOSTNAME", JavaEnvironmentValues.getHostName());
        Machine machine = new Machine(machineName, InternetTools.getPublicIp());
        changes.resourceAdd(machine);
        internalChangeService.changesExecute(changes);

        // Create login database container
        System.out.println("\n===[ Login & UI Databases ]===");
        UnixUser loginDbUnixUser = new UnixUser(UnixUserAvailableIdHelper.getNextAvailableId(), "infra_login_db", "/home/infra_login_db", null, null);
        MariaDBServer loginMariaDBServer = new MariaDBServer(loginConfig.getMysqlDatabaseName() + "_db", "Infra Login Database", SecureRandomTools.randomHexString(25));
        MariaDBDatabase loginMariaDBDatabase = new MariaDBDatabase(loginConfig.getMysqlDatabaseName(), "Infra Login Database");
        MariaDBUser loginMariaDBUser = new MariaDBUser(loginConfig.getMysqlDatabaseUserName(), "Infra Login Database User", loginConfig.getMysqlDatabasePassword());
        changes.resourceAdd(loginDbUnixUser);
        changes.resourceAdd(loginMariaDBServer);
        changes.resourceAdd(loginMariaDBDatabase);
        changes.resourceAdd(loginMariaDBUser);

        changes.linkAdd(loginMariaDBServer, LinkTypeConstants.RUN_AS, loginDbUnixUser);
        changes.linkAdd(loginMariaDBServer, LinkTypeConstants.INSTALLED_ON, machine);

        changes.linkAdd(loginMariaDBDatabase, LinkTypeConstants.INSTALLED_ON, loginMariaDBServer);

        changes.linkAdd(loginMariaDBUser, MariaDBUser.LINK_TYPE_ADMIN, loginMariaDBDatabase);
        changes.linkAdd(loginMariaDBUser, MariaDBUser.LINK_TYPE_READ, loginMariaDBDatabase);
        changes.linkAdd(loginMariaDBUser, MariaDBUser.LINK_TYPE_WRITE, loginMariaDBDatabase);

        // Create ainfra-ui database container
        UnixUser uiDbUnixUser = new UnixUser(UnixUserAvailableIdHelper.getNextAvailableId(), "infra_ui_db", "/home/infra_ui_db", null, null);
        MariaDBServer uiMariaDBServer = new MariaDBServer(infraUiConfig.getMysqlDatabaseName() + "_db", "Infra Ui Database", SecureRandomTools.randomHexString(25));
        MariaDBDatabase uiMariaDBDatabase = new MariaDBDatabase(infraUiConfig.getMysqlDatabaseName(), "Infra Ui Database");
        MariaDBUser uiMariaDBUser = new MariaDBUser(infraUiConfig.getMysqlDatabaseUserName(), "Infra Ui Database User", infraUiConfig.getMysqlDatabasePassword());
        changes.resourceAdd(uiDbUnixUser);
        changes.resourceAdd(uiMariaDBServer);
        changes.resourceAdd(uiMariaDBDatabase);
        changes.resourceAdd(uiMariaDBUser);

        changes.linkAdd(uiMariaDBServer, LinkTypeConstants.RUN_AS, uiDbUnixUser);
        changes.linkAdd(uiMariaDBServer, LinkTypeConstants.INSTALLED_ON, machine);

        changes.linkAdd(uiMariaDBDatabase, LinkTypeConstants.INSTALLED_ON, uiMariaDBServer);

        changes.linkAdd(uiMariaDBUser, MariaDBUser.LINK_TYPE_ADMIN, uiMariaDBDatabase);
        changes.linkAdd(uiMariaDBUser, MariaDBUser.LINK_TYPE_READ, uiMariaDBDatabase);
        changes.linkAdd(uiMariaDBUser, MariaDBUser.LINK_TYPE_WRITE, uiMariaDBDatabase);

        // Create and start infra-ui container
        UnixUser loginUnixUser = new UnixUser(UnixUserAvailableIdHelper.getNextAvailableId(), "infra_login", "/home/infra_login", null, null);
        UnixUser uiUnixUser = new UnixUser(UnixUserAvailableIdHelper.getNextAvailableId(), "infra_ui", "/home/infra_ui", null, null);

        changes.resourceAdd(loginUnixUser);
        changes.resourceAdd(uiUnixUser);

        InfraConfig infraConfig = new InfraConfig();
        infraConfig.setApplicationId(loginConfig.getApplicationId());
        infraConfig.setLoginAdministratorEmail(loginConfig.getAdministratorEmail());
        infraConfig.setLoginCookieSignatureSalt(loginConfig.getCookieSignatureSalt());
        infraConfig.setLoginCsrfSalt(loginConfig.getCsrfSalt());
        infraConfig.setLoginDomainName(loginConfig.getLoginBaseUrl().split("/")[2]);
        infraConfig.setLoginEmailFrom(loginConfig.getFromEmail());
        infraConfig.setUiAlertsToEmail(infraUiConfig.getMailAlertsTo());
        infraConfig.setUiCsrfSalt(infraUiConfig.getCsrfSalt());
        infraConfig.setUiDomainName(infraUiConfig.getBaseUrl().split("/")[2]);
        infraConfig.setUiEmailFrom(infraUiConfig.getMailFrom());

        changes.resourceAdd(infraConfig);

        changes.linkAdd(infraConfig, InfraConfig.LINK_TYPE_LOGIN_INSTALLED_ON, machine);
        changes.linkAdd(infraConfig, InfraConfig.LINK_TYPE_LOGIN_USES, loginMariaDBServer);
        changes.linkAdd(infraConfig, InfraConfig.LINK_TYPE_LOGIN_USES, loginMariaDBDatabase);
        changes.linkAdd(infraConfig, InfraConfig.LINK_TYPE_LOGIN_USES, loginMariaDBUser);
        changes.linkAdd(infraConfig, InfraConfig.LINK_TYPE_LOGIN_USES, loginUnixUser);

        changes.linkAdd(infraConfig, InfraConfig.LINK_TYPE_UI_INSTALLED_ON, machine);
        changes.linkAdd(infraConfig, InfraConfig.LINK_TYPE_UI_USES, uiMariaDBServer);
        changes.linkAdd(infraConfig, InfraConfig.LINK_TYPE_UI_USES, uiMariaDBDatabase);
        changes.linkAdd(infraConfig, InfraConfig.LINK_TYPE_UI_USES, uiMariaDBUser);
        changes.linkAdd(infraConfig, InfraConfig.LINK_TYPE_UI_USES, uiUnixUser);

        // Apply and start
        internalChangeService.changesExecute(changes);
        applyState(resourceService, dockerState);

        // Get the MySql connections
        JdbcTemplate uiJdbcTemplate = getJdbcTemplate( //
                dockerState.getIpByName().get("infra_ui_db"), //
                infraUiConfig.getMysqlPort(), //
                infraUiConfig.getMysqlDatabaseName(), //
                infraUiConfig.getMysqlDatabaseUserName(), //
                infraUiConfig.getMysqlDatabasePassword());

        // Wait for API tables
        System.out.println("\n===[ Wait for the API Users tables to be present ]===");
        AtomicInteger expectedTablesCount = new AtomicInteger();
        while (expectedTablesCount.get() < 2) {
            ThreadTools.sleep(1000);
            expectedTablesCount.set(0);
            uiJdbcTemplate.query("show tables", new RowCallbackHandler() {
                @Override
                public void processRow(ResultSet rs) throws SQLException {
                    String tableName = rs.getString(1);
                    if ("api_machine_user".equals(tableName) || "api_user".equals(tableName)) {
                        expectedTablesCount.incrementAndGet();
                    }
                }
            });
        }

        // Create API user - Admin
        System.out.println("\n===[ Add Admin API user ]===");
        Tuple2<String, String> adminApiIdAndKey = new Tuple2<>(SecureRandomTools.randomHexString(25), SecureRandomTools.randomHexString(25));
        uiJdbcTemplate.update(INSERT_API_USER, true, new Date(), "Bootstrap Admin", DateTools.addDate(Calendar.MINUTE, 15), adminApiIdAndKey.getA(),
                BCrypt.hashpw(adminApiIdAndKey.getB(), BCrypt.gensalt(13)));

        // Create API user - Machine
        System.out.println("\n===[ Add Machine API user ]===");
        Tuple2<String, String> machineApiIdAndKey = new Tuple2<>(SecureRandomTools.randomHexString(25), SecureRandomTools.randomHexString(25));
        uiJdbcTemplate.update(INSERT_API_USER, false, new Date(), "Bootstrap Initial Machine", DateTools.addDate(Calendar.HOUR, 2), machineApiIdAndKey.getA(),
                BCrypt.hashpw(adminApiIdAndKey.getB(), BCrypt.gensalt(13)));
        long machineApiId = uiJdbcTemplate.queryForObject("SELECT id FROM api_user WHERE user_id = ?", Long.class, machineApiIdAndKey.getA());
        uiJdbcTemplate.update(INSERT_API_MACHINE_USER, machineApiId, machine.getName(), adminApiIdAndKey.getB());

        // Get admin user id from login
        System.out.println("\n===[ Get admin user id ]===");
        JdbcTemplate loginJdbcTemplate = getJdbcTemplate( //
                dockerState.getIpByName().get("infra_login_db"), //
                loginConfig.getMysqlPort(), //
                loginConfig.getMysqlDatabaseName(), //
                loginConfig.getMysqlDatabaseUserName(), //
                loginConfig.getMysqlDatabasePassword());
        String adminUserId = loginJdbcTemplate.queryForObject("SELECT user_id FROM user", String.class);
        System.out.println("\tUser admin id: " + adminUserId);

        // Create admin User
        System.out.println("\n===[ Add admin user id ]===");
        uiJdbcTemplate.update(INSERT_USER, true, adminUserId);

        // Wait for UI service to be open
        System.out.println("\n===[ Wait for the API service to be present ]===");
        String infraUiIp = dockerState.getIpByName().get("infra_ui");
        while (true) {
            try {
                new Socket(infraUiIp, 8080).close();
                break;
            } catch (Exception e) {
                ThreadTools.sleep(2000);
            }
        }
        ThreadTools.sleep(10000);

        // Insert base objects via API
        System.out.println("\n===[ Insert base objects via API ]===");
        try {
            InfraApiService infraApiService = new InfraApiServiceImpl("http://" + infraUiIp + ":8080", adminApiIdAndKey.getA(), adminApiIdAndKey.getB());
            ChangesRequest changesRequest = new ChangesRequest();
            List<ResourceDetails> resourcesToAdd = changesRequest.getResourcesToAdd();
            resourcesToAdd.add(new ResourceDetails(resourceService, machine));
            resourcesToAdd.add(new ResourceDetails(resourceService, loginDbUnixUser));
            resourcesToAdd.add(new ResourceDetails(resourceService, loginMariaDBServer));
            resourcesToAdd.add(new ResourceDetails(resourceService, loginMariaDBDatabase));
            resourcesToAdd.add(new ResourceDetails(resourceService, loginMariaDBUser));

            List<LinkDetails> linksToAdd = changesRequest.getLinksToAdd();
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, loginMariaDBServer), LinkTypeConstants.RUN_AS, new ResourceDetails(resourceService, loginDbUnixUser)));
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, loginMariaDBServer), LinkTypeConstants.INSTALLED_ON, new ResourceDetails(resourceService, machine)));

            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, loginMariaDBDatabase), LinkTypeConstants.INSTALLED_ON, new ResourceDetails(resourceService, loginMariaDBServer)));

            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, loginMariaDBUser), MariaDBUser.LINK_TYPE_ADMIN, new ResourceDetails(resourceService, loginMariaDBDatabase)));
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, loginMariaDBUser), MariaDBUser.LINK_TYPE_READ, new ResourceDetails(resourceService, loginMariaDBDatabase)));
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, loginMariaDBUser), MariaDBUser.LINK_TYPE_WRITE, new ResourceDetails(resourceService, loginMariaDBDatabase)));

            resourcesToAdd.add(new ResourceDetails(resourceService, uiDbUnixUser));
            resourcesToAdd.add(new ResourceDetails(resourceService, uiMariaDBServer));
            resourcesToAdd.add(new ResourceDetails(resourceService, uiMariaDBDatabase));
            resourcesToAdd.add(new ResourceDetails(resourceService, uiMariaDBUser));

            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, uiMariaDBServer), LinkTypeConstants.RUN_AS, new ResourceDetails(resourceService, uiDbUnixUser)));
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, uiMariaDBServer), LinkTypeConstants.INSTALLED_ON, new ResourceDetails(resourceService, machine)));

            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, uiMariaDBDatabase), LinkTypeConstants.INSTALLED_ON, new ResourceDetails(resourceService, uiMariaDBServer)));

            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, uiMariaDBUser), MariaDBUser.LINK_TYPE_ADMIN, new ResourceDetails(resourceService, uiMariaDBDatabase)));
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, uiMariaDBUser), MariaDBUser.LINK_TYPE_READ, new ResourceDetails(resourceService, uiMariaDBDatabase)));
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, uiMariaDBUser), MariaDBUser.LINK_TYPE_WRITE, new ResourceDetails(resourceService, uiMariaDBDatabase)));

            resourcesToAdd.add(new ResourceDetails(resourceService, loginUnixUser));
            resourcesToAdd.add(new ResourceDetails(resourceService, uiUnixUser));

            resourcesToAdd.add(new ResourceDetails(resourceService, infraConfig));

            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, infraConfig), InfraConfig.LINK_TYPE_LOGIN_INSTALLED_ON, new ResourceDetails(resourceService, machine)));
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, infraConfig), InfraConfig.LINK_TYPE_LOGIN_USES, new ResourceDetails(resourceService, loginMariaDBServer)));
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, infraConfig), InfraConfig.LINK_TYPE_LOGIN_USES, new ResourceDetails(resourceService, loginMariaDBDatabase)));
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, infraConfig), InfraConfig.LINK_TYPE_LOGIN_USES, new ResourceDetails(resourceService, loginMariaDBUser)));
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, infraConfig), InfraConfig.LINK_TYPE_LOGIN_USES, new ResourceDetails(resourceService, loginUnixUser)));

            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, infraConfig), InfraConfig.LINK_TYPE_UI_INSTALLED_ON, new ResourceDetails(resourceService, machine)));
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, infraConfig), InfraConfig.LINK_TYPE_UI_USES, new ResourceDetails(resourceService, uiMariaDBServer)));
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, infraConfig), InfraConfig.LINK_TYPE_UI_USES, new ResourceDetails(resourceService, uiMariaDBDatabase)));
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, infraConfig), InfraConfig.LINK_TYPE_UI_USES, new ResourceDetails(resourceService, uiMariaDBUser)));
            linksToAdd.add(new LinkDetails(new ResourceDetails(resourceService, infraConfig), InfraConfig.LINK_TYPE_UI_USES, new ResourceDetails(resourceService, uiUnixUser)));

            ResponseWithStatus responseWithStatus = infraApiService.getInfraResourceApiService().applyChanges(changesRequest);

            // Check result
            if (responseWithStatus.isSuccess()) {
                System.out.println("\tSUCCESS");
            } else {
                System.out.println("\tERRORS:");
                for (String error : responseWithStatus.getErrors()) {
                    System.out.println("\t\t" + error);
                }
                applicationContext.close();
                return;
            }
        } catch (HttpClientErrorException e) {
            System.out.println("++++++++++ API Exception ++++++++");
            System.out.println("Response body: " + e.getResponseBodyAsString());
            System.out.println("\nStack Trace:");
            e.printStackTrace();
            System.out.println("++++++++++++++++++++++++++++++++");
        } catch (Exception e) {
            e.printStackTrace();
        }

        // TODO Create and start infra-docker-manager container (persist the docker state)

        // Show information
        System.out.println("\n\nYou can go on " + infraUiConfig.getBaseUrl() + " and use the login " + loginConfig.getAdministratorEmail() + " with password 'qwerty'");
        System.out.println("\n\nPlease note that all your current containers are currently in Fake DNS Mode. " + //
                "It means that all the needed URLs are resolving locally via the /etc/hosts file in each container. " + //
                "When the containers will be rebuilt, that mode will be off, so you need to make sure your DNS Server is well resolving the needed domains.");
        System.out.println();

        applicationContext.close();
    }

}
