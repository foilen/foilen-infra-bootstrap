/*
    Foilen Infra Bootstrap
    https://github.com/foilen/foilen-infra-bootstrap
    Copyright (c) 2017-2019 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.bootstrap.dockerhub;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.foilen.smalltools.tools.AbstractBasics;

@JsonIgnoreProperties(ignoreUnknown = true)
public class DockerHubTagsResponse extends AbstractBasics {

    private List<DockerHubTag> results;

    public List<DockerHubTag> getResults() {
        return results;
    }

    public void setResults(List<DockerHubTag> results) {
        this.results = results;
    }

}
