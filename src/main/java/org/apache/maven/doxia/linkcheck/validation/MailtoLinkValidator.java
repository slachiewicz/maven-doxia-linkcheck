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

import org.apache.maven.doxia.linkcheck.model.LinkcheckFileResult;

/**
 * Validates mailto links.
 *
 * @author <a href="mailto:bwalding@apache.org">Ben Walding</a>
 * @author <a href="mailto:aheritier@apache.org">Arnaud Heritier</a>
 */
public final class MailtoLinkValidator
    implements LinkValidator
{
    /** The (unique) LinkValidationResult to be returned by this LinkValidator. */
    private static final LinkValidationResult LVR =
        new LinkValidationResult( LinkcheckFileResult.VALID_LEVEL, false, "" );

    /** {@inheritDoc} */
    @Override
    public LinkValidationResult validateLink( LinkValidationItem lvi )
    {
        return LVR;
    }

    /** {@inheritDoc} */
    @Override
    public Object getResourceKey( LinkValidationItem lvi )
    {
        if ( lvi.getLink().indexOf( '@' ) != -1 )
        {
            return lvi.getLink();
        }

        return null;
    }
}
