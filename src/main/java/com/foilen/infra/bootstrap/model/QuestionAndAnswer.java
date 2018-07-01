/*
    Foilen Infra Bootstrap
    https://github.com/foilen/foilen-infra-bootstrap
    Copyright (c) 2017-2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.bootstrap.model;

import com.foilen.smalltools.tools.AbstractBasics;

public class QuestionAndAnswer extends AbstractBasics {

    private String question;
    private String answer;

    public QuestionAndAnswer() {
    }

    public QuestionAndAnswer(String question, String answer) {
        this.question = question;
        this.answer = answer;
    }

    public String getAnswer() {
        return answer;
    }

    public String getQuestion() {
        return question;
    }

    public void setAnswer(String answer) {
        this.answer = answer;
    }

    public void setQuestion(String question) {
        this.question = question;
    }

}
