/*
    Foilen Infra Bootstrap
    https://github.com/foilen/foilen-infra-bootstrap
    Copyright (c) 2017-2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.bootstrap;

import org.kohsuke.args4j.Option;

/**
 * The arguments to pass to the infra ui web application.
 */
public class InfraBootstrapOptions {

    @Option(name = "--debug", usage = "To log everything (default: false)")
    public boolean debug;

    @Option(name = "--info", usage = "To log information (default: false)")
    public boolean info;

    @Option(name = "--allDefaults", usage = "To use all the default answers (default: false)")
    public boolean allDefaults;

}
