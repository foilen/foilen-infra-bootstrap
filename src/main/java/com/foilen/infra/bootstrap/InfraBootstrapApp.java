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
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.foilen.infra.api.model.LinkDetails;
import com.foilen.infra.api.model.ResourceDetails;
import com.foilen.infra.api.request.RequestChanges;
import com.foilen.infra.api.response.ResponseMachineSetup;
import com.foilen.infra.api.service.InfraApiService;
import com.foilen.infra.api.service.InfraApiServiceImpl;
import com.foilen.infra.bootstrap.dockerhub.DockerHubTag;
import com.foilen.infra.bootstrap.dockerhub.DockerHubTagsResponse;
import com.foilen.infra.bootstrap.model.OnlineFileDetails;
import com.foilen.infra.bootstrap.model.QuestionAndAnswer;
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
import com.foilen.infra.resource.bind9.Bind9Server;
import com.foilen.infra.resource.dns.DnsEntry;
import com.foilen.infra.resource.dns.model.DnsEntryType;
import com.foilen.infra.resource.infraconfig.InfraConfig;
import com.foilen.infra.resource.infraconfig.InfraConfigPlugin;
import com.foilen.infra.resource.machine.Machine;
import com.foilen.infra.resource.mariadb.MariaDBDatabase;
import com.foilen.infra.resource.mariadb.MariaDBServer;
import com.foilen.infra.resource.mariadb.MariaDBUser;
import com.foilen.infra.resource.unixuser.UnixUser;
import com.foilen.infra.resource.unixuser.helper.UnixUserAvailableIdHelper;
import com.foilen.smalltools.JavaEnvironmentValues;
import com.foilen.smalltools.restapi.model.FormResult;
import com.foilen.smalltools.tools.CollectionsTools;
import com.foilen.smalltools.tools.ConsoleTools;
import com.foilen.smalltools.tools.DateTools;
import com.foilen.smalltools.tools.FileTools;
import com.foilen.smalltools.tools.InternetTools;
import com.foilen.smalltools.tools.JsonTools;
import com.foilen.smalltools.tools.LogbackTools;
import com.foilen.smalltools.tools.ResourceTools;
import com.foilen.smalltools.tools.SecureRandomTools;
import com.foilen.smalltools.tools.SystemTools;
import com.foilen.smalltools.tools.ThreadTools;
import com.foilen.smalltools.tuple.Tuple2;
import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.collect.ComparisonChain;
import com.google.common.io.Files;
import com.mysql.jdbc.jdbc2.optional.MysqlConnectionPoolDataSource;

public class InfraBootstrapApp {

    private static final String INFRA_DOCKER_MANAGER_NAME = "infra_docker_manager";

    private static final String INSERT_API_USER = "INSERT INTO api_user(is_admin, created_on, description, expire_on, user_id, user_hashed_key, version) VALUES(?, ?, ?, ?, ?, ?, 0)";
    private static final String INSERT_USER = "INSERT INTO user(is_admin, user_id, version) VALUES(?, ?, 0)";

    private static final String INSERT_API_MACHINE_USER = "INSERT INTO api_machine_user(id, machine_name, user_key) VALUES(?, ?, ?)";

    private static BufferedReader br;

    private static InfraBootstrapOptions options;

    private static RestTemplate restTemplate = new RestTemplate();
    private static DockerUtils dockerUtils = new DockerUtilsImpl();

    private static File tmpDirectory = Files.createTempDir();
    private static Map<String, String> answers = new HashMap<>();
    private static List<QuestionAndAnswer> genAnswers = new ArrayList<>();

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
                fakeDnsHostsEntries.add("172.17.0.1 " + dnsEntry.getName() + " #FakeDNS");
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
            outputContext.setDockerLogsMaxSizeMB(100);
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

    private static void createNewCluster() {

        // Load the json answer file if present
        if (!options.genJsonAnswers && !Strings.isNullOrEmpty(options.jsonAnswerFile)) {
            List<QuestionAndAnswer> questionAndAnswers = JsonTools.readFromFileAsList(options.jsonAnswerFile, QuestionAndAnswer.class);
            questionAndAnswers.forEach(it -> answers.put(it.getQuestion(), it.getAnswer()));
        }

        // Get the latest version of apps
        OnlineFileDetails loginVersionDetails = getLatestVersionDockerHub("foilen/foilen-login");
        String loginLatestVersion = "latest";
        if (loginVersionDetails != null) {
            loginLatestVersion = loginVersionDetails.getVersion();
        }
        OnlineFileDetails uiVersionDetails = getLatestVersionDockerHub("foilen/foilen-infra-ui");
        String uiLatestVersion = "latest";
        if (uiVersionDetails != null) {
            uiLatestVersion = uiVersionDetails.getVersion();
        }

        // Prepare config
        InfraUiConfig infraUiConfig = new InfraUiConfig();
        infraUiConfig.setMailFrom(getText("[COMMON] Email address that sends information and alerts (mail from)", "infra-ui@localhost.foilen-lab.com").toLowerCase());
        infraUiConfig.setMailAlertsTo(getText("[COMMON] Email address where to send alerts", "admin@localhost.foilen-lab.com").toLowerCase());
        infraUiConfig.setMailHost(getText("[COMMON] Email server hostname/ip", "127.0.0.1"));
        infraUiConfig.setMailPort(getInt("[COMMON] Email server port", 25));
        infraUiConfig.setMailUsername(getText("[COMMON] Email server username", null));
        infraUiConfig.setMailPassword(getText("[COMMON] Email server password", null));

        infraUiConfig.setCsrfSalt(SecureRandomTools.randomHexString(25));

        String uiVersion = getText("[UI] Docker Image Version", uiLatestVersion);
        infraUiConfig.setBaseUrl(getText("[UI] Base URL", "http://infra.localhost.foilen-lab.com").toLowerCase());
        // TODO Support HTTPS

        infraUiConfig.setMysqlDatabaseName(getText("[UI] MySQL Database Name", "infra_ui").toLowerCase());
        infraUiConfig.setMysqlDatabaseUserName(getText("[UI] MySQL Database User Name", "infra_ui").toLowerCase());
        infraUiConfig.setMysqlDatabasePassword(getText("[UI] MySQL Database User Password", SecureRandomTools.randomHexString(25)).toLowerCase());
        infraUiConfig.setLoginCookieSignatureSalt(SecureRandomTools.randomHexString(25));

        infraUiConfig.getLoginConfigDetails().setAppId(SecureRandomTools.randomHexString(10));
        String loginVersion = getText("[Login] Docker Image Version", loginLatestVersion);
        infraUiConfig.getLoginConfigDetails().setBaseUrl(getText("[LOGIN] Base URL", "http://login.localhost.foilen-lab.com").toLowerCase());
        InfraLoginConfig loginConfig = new InfraLoginConfig();
        loginConfig.setAdministratorEmail(infraUiConfig.getMailAlertsTo());
        loginConfig.setApplicationId(infraUiConfig.getLoginConfigDetails().getAppId());
        loginConfig.setCookieDateName((getText("[LOGIN] Cookie Date Name", "l_date").toLowerCase()));
        loginConfig.setCookieSignatureName(getText("[LOGIN] Cookie Signature Name", "l_sign").toLowerCase());
        loginConfig.setCookieSignatureSalt(SecureRandomTools.randomHexString(25));
        loginConfig.setCookieUserName(getText("[LOGIN] Cookie Username Name", "l_username").toLowerCase());
        loginConfig.setCsrfSalt(SecureRandomTools.randomHexString(25));
        loginConfig.setFromEmail(infraUiConfig.getMailFrom());
        loginConfig.setMailHost(infraUiConfig.getMailHost());
        loginConfig.setMailPort(infraUiConfig.getMailPort());
        loginConfig.setMailUsername(infraUiConfig.getMailUsername());
        loginConfig.setMailPassword(infraUiConfig.getMailPassword());
        loginConfig.setLoginBaseUrl(infraUiConfig.getLoginConfigDetails().getBaseUrl());
        loginConfig.setMysqlDatabaseName(getText("[LOGIN] MySQL Database Name", "infra_login").toLowerCase());
        loginConfig.setMysqlHostName("127.0.0.1");
        loginConfig.setMysqlDatabaseUserName(getText("[LOGIN] MySQL Database User Name", "infra_login").toLowerCase());
        loginConfig.setMysqlDatabasePassword(getText("[LOGIN] MySQL Database User Password", SecureRandomTools.randomHexString(25)).toLowerCase());

        // Prepare Bind9
        Bind9Server bind9Server = new Bind9Server();
        bind9Server.setName("infra");
        bind9Server.setAdminEmail(infraUiConfig.getMailAlertsTo());
        bind9Server.getNsDomainNames().add(getText("[DNS] Name Server Domain", "ns1.localhost.foilen-lab.com").toLowerCase());

        // Save gen to file if requested
        if (!genAnswers.isEmpty()) {
            System.out.println("Saving questions and answers to " + options.jsonAnswerFile);
            JsonTools.writeToFile(options.jsonAnswerFile, genAnswers);
            return;
        }

        System.out.println("\nReview the config:");
        System.out.println("---[ Login ]---");
        System.out.println(JsonTools.prettyPrint(loginConfig));
        System.out.println("---[ UI ]---");
        System.out.println(JsonTools.prettyPrint(infraUiConfig));
        System.out.println("Press enter to continue...");
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

        // Docker Manager
        UnixUser managerUnixUser = new UnixUser(UnixUserAvailableIdHelper.getNextAvailableId(), INFRA_DOCKER_MANAGER_NAME, "/home/infra_docker_manager", null, null);
        changes.resourceAdd(managerUnixUser);

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

        // Create infra-ui database container
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
        infraConfig.setLoginDomainName(loginConfig.getLoginBaseUrl().split("/")[2]);
        infraConfig.setLoginEmailFrom(loginConfig.getFromEmail());
        infraConfig.setLoginAdministratorEmail(loginConfig.getAdministratorEmail());
        infraConfig.setMailHost(loginConfig.getMailHost());
        infraConfig.setMailPort(loginConfig.getMailPort());
        infraConfig.setMailUsername(loginConfig.getMailUsername());
        infraConfig.setMailPassword(loginConfig.getMailPassword());
        infraConfig.setLoginCsrfSalt(loginConfig.getCsrfSalt());
        infraConfig.setLoginCookieSignatureSalt(loginConfig.getCookieSignatureSalt());
        infraConfig.setLoginVersion(loginVersion);
        infraConfig.setUiDomainName(infraUiConfig.getBaseUrl().split("/")[2]);
        infraConfig.setUiEmailFrom(infraUiConfig.getMailFrom());
        infraConfig.setUiAlertsToEmail(infraUiConfig.getMailAlertsTo());
        infraConfig.setUiCsrfSalt(infraUiConfig.getCsrfSalt());
        infraConfig.setUiVersion(uiVersion);

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

        // Get the most recent plugins
        System.out.println("\n===[ Get the most recent plugins list ]===");
        List<String> pluginNames = Arrays.asList("apachephp", "application", "bind9", "composableapplication", "dns", "email", "infraconfig", "letsencrypt", "machine", "mariadb", "unixuser",
                "urlredirection", "webcertificate", "website");
        List<InfraConfigPlugin> infraConfigPlugins = new ArrayList<>();
        for (String nextPlugin : pluginNames) {
            System.out.println("Plugin: " + nextPlugin);

            try {
                OnlineFileDetails onlineFileDetails = getLatestVersionBintray("foilen-infra-resource-" + nextPlugin);

                System.out.println("\tVersion: " + onlineFileDetails.getVersion() + " URL: " + onlineFileDetails.getJarUrl());

                InfraConfigPlugin infraConfigPlugin = new InfraConfigPlugin(onlineFileDetails.getJarUrl(), null);
                infraConfigPlugins.add(infraConfigPlugin);
                changes.resourceAdd(infraConfigPlugin);
                changes.linkAdd(infraConfig, InfraConfig.LINK_TYPE_UI_USES, infraConfigPlugin);
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(1);
            }

        }

        // Create Bind9
        UnixUser bind9UnixUser = new UnixUser(UnixUserAvailableIdHelper.getNextAvailableId(), "infra_bind9", "/home/infra_bind9", null, null);
        if (!options.noDnsServer) {
            changes.resourceAdd(bind9Server);
            changes.resourceAdd(bind9UnixUser);
            changes.linkAdd(bind9Server, LinkTypeConstants.RUN_AS, bind9UnixUser);
            changes.linkAdd(bind9Server, LinkTypeConstants.INSTALLED_ON, machine);
        }

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
                BCrypt.hashpw(machineApiIdAndKey.getB(), BCrypt.gensalt(13)));
        long machineApiId = uiJdbcTemplate.queryForObject("SELECT id FROM api_user WHERE user_id = ?", Long.class, machineApiIdAndKey.getA());
        uiJdbcTemplate.update(INSERT_API_MACHINE_USER, machineApiId, machine.getName(), machineApiIdAndKey.getB());

        // Get admin user id from login
        System.out.println("\n===[ Get admin user id ]===");
        JdbcTemplate loginJdbcTemplate = getJdbcTemplate( //
                dockerState.getIpByName().get("infra_login_db"), //
                loginConfig.getMysqlPort(), //
                loginConfig.getMysqlDatabaseName(), //
                loginConfig.getMysqlDatabaseUserName(), //
                loginConfig.getMysqlDatabasePassword());
        String adminUserId = null;
        while (adminUserId == null) {
            try {
                ThreadTools.sleep(500);
                adminUserId = loginJdbcTemplate.queryForObject("SELECT user_id FROM user", String.class);
            } catch (Exception e) {
            }
        }
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
            RequestChanges changesRequest = new RequestChanges();
            List<ResourceDetails> resourcesToAdd = changesRequest.getResourcesToAdd();
            resourcesToAdd.add(new ResourceDetails("Machine", machine));

            resourcesToAdd.add(new ResourceDetails("Unix User", loginDbUnixUser));
            resourcesToAdd.add(new ResourceDetails("MariaDB Server", loginMariaDBServer));
            resourcesToAdd.add(new ResourceDetails("MariaDB Database", loginMariaDBDatabase));
            resourcesToAdd.add(new ResourceDetails("MariaDB User", loginMariaDBUser));

            List<LinkDetails> linksToAdd = changesRequest.getLinksToAdd();
            linksToAdd.add(new LinkDetails(new ResourceDetails("MariaDB Server", loginMariaDBServer), LinkTypeConstants.RUN_AS, new ResourceDetails("Unix User", loginDbUnixUser)));
            linksToAdd.add(new LinkDetails(new ResourceDetails("MariaDB Server", loginMariaDBServer), LinkTypeConstants.INSTALLED_ON, new ResourceDetails("Machine", machine)));

            linksToAdd.add(new LinkDetails(new ResourceDetails("MariaDB Database", loginMariaDBDatabase), LinkTypeConstants.INSTALLED_ON, new ResourceDetails("MariaDB Server", loginMariaDBServer)));

            linksToAdd.add(new LinkDetails(new ResourceDetails("MariaDB User", loginMariaDBUser), MariaDBUser.LINK_TYPE_ADMIN, new ResourceDetails("MariaDB Database", loginMariaDBDatabase)));
            linksToAdd.add(new LinkDetails(new ResourceDetails("MariaDB User", loginMariaDBUser), MariaDBUser.LINK_TYPE_READ, new ResourceDetails("MariaDB Database", loginMariaDBDatabase)));
            linksToAdd.add(new LinkDetails(new ResourceDetails("MariaDB User", loginMariaDBUser), MariaDBUser.LINK_TYPE_WRITE, new ResourceDetails("MariaDB Database", loginMariaDBDatabase)));

            resourcesToAdd.add(new ResourceDetails("Unix User", uiDbUnixUser));
            resourcesToAdd.add(new ResourceDetails("MariaDB Server", uiMariaDBServer));
            resourcesToAdd.add(new ResourceDetails("MariaDB Database", uiMariaDBDatabase));
            resourcesToAdd.add(new ResourceDetails("MariaDB User", uiMariaDBUser));

            linksToAdd.add(new LinkDetails(new ResourceDetails("MariaDB Server", uiMariaDBServer), LinkTypeConstants.RUN_AS, new ResourceDetails("Unix User", uiDbUnixUser)));
            linksToAdd.add(new LinkDetails(new ResourceDetails("MariaDB Server", uiMariaDBServer), LinkTypeConstants.INSTALLED_ON, new ResourceDetails("Machine", machine)));

            linksToAdd.add(new LinkDetails(new ResourceDetails("MariaDB Database", uiMariaDBDatabase), LinkTypeConstants.INSTALLED_ON, new ResourceDetails("MariaDB Server", uiMariaDBServer)));

            linksToAdd.add(new LinkDetails(new ResourceDetails("MariaDB User", uiMariaDBUser), MariaDBUser.LINK_TYPE_ADMIN, new ResourceDetails("MariaDB Database", uiMariaDBDatabase)));
            linksToAdd.add(new LinkDetails(new ResourceDetails("MariaDB User", uiMariaDBUser), MariaDBUser.LINK_TYPE_READ, new ResourceDetails("MariaDB Database", uiMariaDBDatabase)));
            linksToAdd.add(new LinkDetails(new ResourceDetails("MariaDB User", uiMariaDBUser), MariaDBUser.LINK_TYPE_WRITE, new ResourceDetails("MariaDB Database", uiMariaDBDatabase)));

            resourcesToAdd.add(new ResourceDetails("Unix User", loginUnixUser));
            resourcesToAdd.add(new ResourceDetails("Unix User", uiUnixUser));

            resourcesToAdd.add(new ResourceDetails("Infrastructure Configuration", infraConfig));

            linksToAdd.add(new LinkDetails(new ResourceDetails("Infrastructure Configuration", infraConfig), InfraConfig.LINK_TYPE_LOGIN_INSTALLED_ON, new ResourceDetails("Machine", machine)));
            linksToAdd.add(
                    new LinkDetails(new ResourceDetails("Infrastructure Configuration", infraConfig), InfraConfig.LINK_TYPE_LOGIN_USES, new ResourceDetails("MariaDB Server", loginMariaDBServer)));
            linksToAdd.add(
                    new LinkDetails(new ResourceDetails("Infrastructure Configuration", infraConfig), InfraConfig.LINK_TYPE_LOGIN_USES, new ResourceDetails("MariaDB Database", loginMariaDBDatabase)));
            linksToAdd.add(new LinkDetails(new ResourceDetails("Infrastructure Configuration", infraConfig), InfraConfig.LINK_TYPE_LOGIN_USES, new ResourceDetails("MariaDB User", loginMariaDBUser)));
            linksToAdd.add(new LinkDetails(new ResourceDetails("Infrastructure Configuration", infraConfig), InfraConfig.LINK_TYPE_LOGIN_USES, new ResourceDetails("Unix User", loginUnixUser)));

            linksToAdd.add(new LinkDetails(new ResourceDetails("Infrastructure Configuration", infraConfig), InfraConfig.LINK_TYPE_UI_INSTALLED_ON, new ResourceDetails("Machine", machine)));
            linksToAdd.add(new LinkDetails(new ResourceDetails("Infrastructure Configuration", infraConfig), InfraConfig.LINK_TYPE_UI_USES, new ResourceDetails("MariaDB Server", uiMariaDBServer)));
            linksToAdd
                    .add(new LinkDetails(new ResourceDetails("Infrastructure Configuration", infraConfig), InfraConfig.LINK_TYPE_UI_USES, new ResourceDetails("MariaDB Database", uiMariaDBDatabase)));
            linksToAdd.add(new LinkDetails(new ResourceDetails("Infrastructure Configuration", infraConfig), InfraConfig.LINK_TYPE_UI_USES, new ResourceDetails("MariaDB User", uiMariaDBUser)));
            linksToAdd.add(new LinkDetails(new ResourceDetails("Infrastructure Configuration", infraConfig), InfraConfig.LINK_TYPE_UI_USES, new ResourceDetails("Unix User", uiUnixUser)));

            // Add plugins
            infraConfigPlugins.forEach(plugin -> {
                resourcesToAdd.add(new ResourceDetails("Infrastructure Plugin", plugin));
                linksToAdd.add(new LinkDetails(new ResourceDetails("Infrastructure Configuration", infraConfig), InfraConfig.LINK_TYPE_UI_USES, new ResourceDetails("Infrastructure Plugin", plugin)));
            });

            // Bind9
            if (!options.noDnsServer) {
                resourcesToAdd.add(new ResourceDetails("Bind9 Server", bind9Server));
                resourcesToAdd.add(new ResourceDetails("Unix User", bind9UnixUser));

                linksToAdd.add(new LinkDetails(new ResourceDetails("Bind9 Server", bind9Server), LinkTypeConstants.RUN_AS, new ResourceDetails("Unix User", bind9UnixUser)));
                linksToAdd.add(new LinkDetails(new ResourceDetails("Bind9 Server", bind9Server), LinkTypeConstants.INSTALLED_ON, new ResourceDetails("Machine", machine)));
            }

            // Any missing unix users
            Set<String> alreadyKnownUnixUsers = changesRequest.getResourcesToAdd().stream() //
                    .filter(it -> it.getResourceType().equals("Unix User")) //
                    .map(it -> (UnixUser) it.getResource()) //
                    .map(it -> it.getName()) //
                    .collect(Collectors.toSet());
            resourceService.resourceFindAll(resourceService.createResourceQuery(UnixUser.class)).stream() //
                    .filter(it -> !alreadyKnownUnixUsers.contains(it.getName())) //
                    .forEach(it -> resourcesToAdd.add(new ResourceDetails("Unix User", it)));

            FormResult formResult = infraApiService.getInfraResourceApiService().applyChanges(changesRequest);

            // Check result
            if (formResult.isSuccess()) {
                System.out.println("\tSUCCESS");
            } else {
                System.out.println("\tERRORS:");
                for (String error : formResult.getGlobalErrors()) {
                    System.out.println("\t\t" + error);
                }
                if (formResult.getError() != null) {
                    System.out.println("\t\t" + formResult.getError());
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
            System.exit(1);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

        // Create and start infra-docker-manager container
        if (options.startDockerManager) {

            // Application details
            OnlineFileDetails dockerManagerVersion = getLatestVersionDockerHub("foilen/foilen-infra-docker-manager");

            // Start
            File startFile;
            try {
                startFile = File.createTempFile("start-docker-manager", ".sh");
                FileTools.changePermissions(startFile.getAbsolutePath(), false, "700");
                FileTools.writeFile(ResourceTools.getResourceAsString("start-docker-manager.sh", InfraBootstrapApp.class), startFile);
            } catch (IOException e) {
                throw new InfraBootstrapException("Problem creating start script", e);
            }

            int status = ConsoleTools.executeAndWait(new String[] { //
                    startFile.getAbsolutePath(), //
                    dockerManagerVersion.getVersion(), //
                    infraUiConfig.getBaseUrl(), //
                    machineApiIdAndKey.getA(), machineApiIdAndKey.getB(), //
                    machineName //
            });
            if (status != 0) {
                throw new InfraBootstrapException("Problem starting docker manager");
            }

            // Show information
            System.out.println("\n\nThe Docker Manager version " + dockerManagerVersion.getVersion() + " is installed");
            System.out.println();

        }

        // Show information
        System.out.println("\n\nYou can go on " + infraUiConfig.getBaseUrl() + " and use the login " + loginConfig.getAdministratorEmail() + " with password 'qwerty'");
        System.out.println("\n\nPlease note that all your current containers are currently in Fake DNS Mode. " + //
                "It means that all the needed URLs are resolving locally via the /etc/hosts file in each container. " + //
                "When the containers will be rebuilt, that mode will be off, so you need to make sure your DNS Server is well resolving the needed domains.");
        System.out.println();

        applicationContext.close();
    }

    private static int getInt(String prompt, int defaultValue) {

        while (true) {
            String textValue = getText(prompt, String.valueOf(defaultValue));
            try {
                return Integer.valueOf(textValue);
            } catch (Exception e) {
                System.out.println("\t[ERROR] Must be numeric");
            }
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

    private static OnlineFileDetails getLatestVersionBintray(String packageName) {
        try {
            // Get the version
            Document doc = Jsoup.connect("https://dl.bintray.com/foilen/maven/com/foilen/" + packageName).get();
            Elements links = doc.select("a");
            String version = links.stream() //
                    .map(it -> it.text().replace("/", "")) //
                    .map(it -> it.split("\\.")) //
                    .filter(it -> it.length == 3) //
                    .map(it -> new int[] { Integer.valueOf(it[0]), Integer.valueOf(it[1]), Integer.valueOf(it[2]) }) //
                    .sorted((a, b) -> ComparisonChain.start() //
                            .compare(b[0], a[0]) //
                            .compare(b[1], a[1]) //
                            .compare(b[2], a[2]) //
                            .result()) //
                    .map(it -> "" + it[0] + "." + it[1] + "." + it[2]) //
                    .findFirst().get(); //

            // Get the jar
            String jarUrl = "https://dl.bintray.com/foilen/maven/com/foilen/" + packageName + "/" + version + "/" + packageName + "-" + version + ".jar";

            OnlineFileDetails onlineFileDetails = new OnlineFileDetails();
            onlineFileDetails.setJarUrl(jarUrl);
            onlineFileDetails.setVersion(version);
            return onlineFileDetails;
        } catch (IOException e) {
            throw new InfraBootstrapException("Problem getting the folder", e);
        }

    }

    private static OnlineFileDetails getLatestVersionDockerHub(String imageName) {
        DockerHubTagsResponse tags = restTemplate.getForObject("https://hub.docker.com/v2/repositories/{imageName}/tags/", DockerHubTagsResponse.class,
                Collections.singletonMap("imageName", imageName));

        Optional<DockerHubTag> tag = tags.getResults().stream() //
                .filter(it -> !"latest".equals(it.getName())) //
                .findFirst();

        if (tag.isPresent()) {
            return new OnlineFileDetails() //
                    .setVersion(tag.get().getName());
        }

        return null;
    }

    private static String getLine() {
        try {
            return br.readLine();
        } catch (IOException e) {
            throw new InfraBootstrapException(e);
        }
    }

    private static String getText(String prompt, String defaultValue) {

        // Fill Q&A if generating it
        if (options.genJsonAnswers) {
            genAnswers.add(new QuestionAndAnswer(prompt, defaultValue));
            return defaultValue;
        }

        // Prompt
        if (defaultValue == null) {
            System.out.print(prompt + " [] ");
        } else {
            System.out.print(prompt + " [" + defaultValue + "] ");
        }

        // Auto answer from JSON file
        if (!Strings.isNullOrEmpty(options.jsonAnswerFile)) {
            String value = answers.get(prompt);
            System.out.println(value);
            return value;
        }

        // Auto answer with default
        if (options.allDefaults) {
            System.out.println();
            return defaultValue;
        }

        // Get interactive input
        String input = getLine();
        if (Strings.isNullOrEmpty(input)) {
            return defaultValue;
        }

        return input;
    }

    private static void joinExistingCluster() {

        String machineName = SystemTools.getPropertyOrEnvironment("MACHINE_HOSTNAME", JavaEnvironmentValues.getHostName());

        // Get the Machine Setup
        System.out.println("\n---[ Get the Machine Setup ]---");
        InfraApiService infraApiService = new InfraApiServiceImpl(options.uiApiBaseUrl, options.uiApiUserId, options.uiApiUserKey);
        ResponseMachineSetup machineSetup = infraApiService.getInfraMachineApiService().getMachineSetup(machineName);

        // Install unix users
        System.out.println("\n---[ Install unix users ]---");
        UnixUsersAndGroupsUtils unixUsersAndGroupsUtils = new UnixUsersAndGroupsUtilsImpl();
        for (UnixUser unixUser : machineSetup.getItem().getUnixUsers()) {
            System.out.println("\t" + unixUser.getName() + " (" + unixUser.getId() + ")");
            unixUsersAndGroupsUtils.userCreate(unixUser.getName(), unixUser.getId(), unixUser.getHomeFolder(), null, null);
        }

        // Application details
        OnlineFileDetails dockerManagerVersion = getLatestVersionDockerHub("foilen/foilen-infra-docker-manager");

        // Start
        File startFile;
        try {
            startFile = File.createTempFile("start-docker-manager", ".sh");
            FileTools.changePermissions(startFile.getAbsolutePath(), false, "700");
            FileTools.writeFile(ResourceTools.getResourceAsString("start-docker-manager.sh", InfraBootstrapApp.class), startFile);
        } catch (IOException e) {
            throw new InfraBootstrapException("Problem creating start script", e);
        }

        int status = ConsoleTools.executeAndWait(new String[] { //
                startFile.getAbsolutePath(), //
                dockerManagerVersion.getVersion(), //
                options.uiApiBaseUrl, //
                options.uiApiUserId, options.uiApiUserKey, //
                machineName //
        });
        if (status != 0) {
            throw new InfraBootstrapException("Problem starting docker manager");
        }

        // Show information
        System.out.println("\n\nThe Docker Manager version " + dockerManagerVersion.getVersion() + " is installed");
        System.out.println();

    }

    public static void main(String[] args) {

        if (br == null) {
            br = new BufferedReader(new InputStreamReader(System.in));
        }

        // Get the parameters
        options = new InfraBootstrapOptions();
        CmdLineParser cmdLineParser = new CmdLineParser(options);
        try {
            cmdLineParser.parseArgument(args);
        } catch (CmdLineException e) {
            e.printStackTrace();
            showUsage();
            return;
        }

        // Check help
        if (options.help) {
            showUsage();
            return;
        }

        // Check valid options
        if (options.genJsonAnswers && Strings.isNullOrEmpty(options.jsonAnswerFile)) {
            System.out.println("When generating the answers, you must also specify in which file using --jsonAnswerFile");
            return;
        }
        if (options.join) {
            if (!CollectionsTools.isAllItemNotNull(options.uiApiBaseUrl, options.uiApiUserId, options.uiApiUserKey)) {
                System.out.println("When joining an existing cluster, you must specify --uiApiBaseUrl, --uiApiUserId and --uiApiUserKey");
                return;
            }
        }

        // Check the logging mode
        if (options.debug) {
            LogbackTools.changeConfig("/logback-debug.xml");
        } else if (options.info) {
            LogbackTools.changeConfig("/logback-info.xml");
        } else {
            LogbackTools.changeConfig("/logback-quiet.xml");
        }

        // Create or join
        if (options.join) {
            joinExistingCluster();
        } else {
            createNewCluster();
        }
    }

    private static void showUsage() {
        System.out.println("Usage:");
        CmdLineParser cmdLineParser = new CmdLineParser(new InfraBootstrapOptions());
        cmdLineParser.printUsage(System.out);
    }

}
