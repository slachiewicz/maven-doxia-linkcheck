package org.apache.maven.doxia.linkcheck.validation;

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

import junit.framework.TestCase;

/**
 * @author <a href="mailto:vincent.siveton@gmail.com">Vincent Siveton</a>
 */
public class LinkValidatorManagerTest
    extends TestCase
{

    public void testMatchPattern() throws Exception
    {
        String link = "http://maven.apache.org";
        String pattern = "http://maven.apache.org";
        assertTrue( LinkValidatorManager.matchPattern( link, pattern ) );

        link = "http://maven.apache.org/";
        pattern = "http://maven.apache.org";
        assertTrue( LinkValidatorManager.matchPattern( link, pattern ) );

        link = "http://maven.apache.org";
        pattern = "http://maven.apache.org/";
        assertTrue( LinkValidatorManager.matchPattern( link, pattern ) );

        link = "http://maven.apache.org/test.html";
        pattern = "http://maven.apache.org/";
        assertTrue( LinkValidatorManager.matchPattern( link, pattern ) );

        link = "http://maven.apache.org";
        pattern = "http://maven.apache.org/*";
        assertTrue( LinkValidatorManager.matchPattern( link, pattern ) );
        assertTrue( LinkValidatorManager.matchPattern( link + "/", pattern ) );

        link = "http://maven.apache.org/test/test.html";
        pattern = "http://maven.apache.org/**/*";
        assertTrue( LinkValidatorManager.matchPattern( link, pattern ) );

        link = "http://maven.apache.org/test/test.html";
        pattern = "http://maven.apache.org/*.html";
        assertTrue( LinkValidatorManager.matchPattern( link, pattern ) );

        link = "http://maven.apache.org/test/test.html";
        pattern = "http://maven.apache.org/**/*.jsp";
        assertFalse( LinkValidatorManager.matchPattern( link, pattern ) );

        link = "http://java.sun.com/";
        pattern = "../../exclude/*";
        assertFalse( LinkValidatorManager.matchPattern( link, pattern ) );
    }
}
