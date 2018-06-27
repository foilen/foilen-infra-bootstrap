/*
    Foilen Infra Bootstrap
    https://github.com/foilen/foilen-infra-bootstrap
    Copyright (c) 2017-2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.bootstrap;

public class OnlineFileDetails {

    private String version;
    private String jarUrl;

    public String getJarUrl() {
        return jarUrl;
    }

    public String getVersion() {
        return version;
    }

    public void setJarUrl(String jarUrl) {
        this.jarUrl = jarUrl;
    }

    public void setVersion(String version) {
        this.version = version;
    }

}
