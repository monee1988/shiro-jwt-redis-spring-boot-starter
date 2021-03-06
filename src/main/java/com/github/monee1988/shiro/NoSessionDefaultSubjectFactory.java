package com.github.monee1988.shiro;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;

/**
 * @author monee1988
 * @version 1.0
 * @date 2022-05-23 20:38
 */
@Slf4j
public class NoSessionDefaultSubjectFactory extends DefaultWebSubjectFactory {

    @Override
    public Subject createSubject(SubjectContext context) {
        //不创建shiro内部的session
        log.debug("NoSessionDefaultSubjectFactory set SessionCreationEnabled false ");
        context.setSessionCreationEnabled(false);
        return super.createSubject(context);
    }
}
