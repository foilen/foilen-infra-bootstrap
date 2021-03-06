/*
    Foilen Infra Bootstrap
    https://github.com/foilen/foilen-infra-bootstrap
    Copyright (c) 2017-2021 Foilen (https://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.bootstrap;

import org.kohsuke.args4j.Option;

/**
 * The arguments to pass to the infra ui web application.
 */
public class InfraBootstrapOptions {

    @Option(name = "--help", usage = "To show this help")
    public boolean help;

    @Option(name = "--debug", usage = "To log everything")
    public boolean debug;
    @Option(name = "--info", usage = "To log information")
    public boolean info;

    // Create a new cluster
    @Option(name = "--genJsonAnswers", usage = "To generate a JSON file with all the questions and defaults answers, then stop")
    public boolean genJsonAnswers;
    @Option(name = "--allDefaults", usage = "To use all the default answers")
    public boolean allDefaults;
    @Option(name = "--jsonAnswerFile", metaVar = "file", usage = "To use a JSON file with all the questions and answers (default: none)")
    public String jsonAnswerFile;

    @Option(name = "--noDnsServer", usage = "To not install the Bind9 DNS Server")
    public boolean noDnsServer;

    @Option(name = "--startDockerManager", usage = "To start Docker Manager that will use this new cluster")
    public boolean startDockerManager;

    // Join an existing cluster
    @Option(name = "--join", usage = "To join an existing cluster")
    public boolean join;
    @Option(name = "--uiApiBaseUrl", metaVar = "url", usage = "The base url of the UI to join")
    public String uiApiBaseUrl;
    @Option(name = "--uiApiUserId", metaVar = "id", usage = "The machine user id for the UI to join")
    public String uiApiUserId;
    @Option(name = "--uiApiUserKey", metaVar = "key", usage = "The machine user key for the UI to join")
    public String uiApiUserKey;

}
