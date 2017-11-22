/*
    Foilen Infra Bootstrap
    https://github.com/foilen/foilen-infra-bootstrap
    Copyright (c) 2017 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.bootstrap;

public class InfraBootstrapException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public InfraBootstrapException(String message) {
        super(message);
    }

    public InfraBootstrapException(String message, Throwable cause) {
        super(message, cause);
    }

    public InfraBootstrapException(Throwable cause) {
        super(cause);
    }

}
