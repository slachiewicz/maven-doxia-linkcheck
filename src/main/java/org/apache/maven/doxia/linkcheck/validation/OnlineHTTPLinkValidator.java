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

import java.io.IOException;

import java.net.URL;
import java.util.Map;

import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.HttpState;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.NTCredentials;
import org.apache.commons.httpclient.StatusLine;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.HeadMethod;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.params.HttpMethodParams;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.maven.doxia.linkcheck.HttpBean;
import org.apache.maven.doxia.linkcheck.model.LinkcheckFileResult;
import org.codehaus.plexus.util.StringUtils;

/**
 * Checks links which are normal URLs
 *
 * @author <a href="mailto:bwalding@apache.org">Ben Walding</a>
 * @author <a href="mailto:aheritier@apache.org">Arnaud Heritier</a>
 * @author <a href="mailto:vincent.siveton@gmail.com">Vincent Siveton</a>
 */
public final class OnlineHTTPLinkValidator
    extends HTTPLinkValidator
{
    /** Log for debug output. */
    private static final Log LOG = LogFactory.getLog( OnlineHTTPLinkValidator.class );

    /** The maximum number of redirections for a link. */
    private static final int MAX_NB_REDIRECT = 10;

    /** Use the get method to test pages. */
    private static final String GET_METHOD = "get";

    /** Use the head method to test pages. */
    private static final String HEAD_METHOD = "head";

    /** The http bean encapsuling all http parameters supported. */
    private HttpBean http;

    /** The base URL for links that start with '/'. */
    private String baseURL;

    /** The HttpClient. */
    private transient HttpClient cl;

    /**
     * Constructor: initialize settings, use "head" method.
     */
    public OnlineHTTPLinkValidator()
    {
        this( new HttpBean() );
    }

    /**
     * Constructor: initialize settings.
     *
     * @param bean The http bean encapsuling all HTTP parameters supported.
     */
    public OnlineHTTPLinkValidator( HttpBean bean )
    {
        if ( bean == null )
        {
            bean = new HttpBean();
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( "Will use method : [" + bean.getMethod() + "]" );
        }

        this.http = bean;

        initHttpClient();
    }

    /**
     * The base URL.
     *
     * @return the base URL.
     */
    public String getBaseURL()
    {
        return this.baseURL;
    }

    /**
     * Sets the base URL. This is pre-pended to links that start with '/'.
     *
     * @param url the base URL.
     */
    public void setBaseURL( String url )
    {
        this.baseURL = url;
    }

    /** {@inheritDoc} */
    @Override
    public LinkValidationResult validateLink( LinkValidationItem lvi )
    {
        if ( this.cl == null )
        {
            initHttpClient();
        }

        if ( this.http.getHttpClientParameters() != null )
        {
            for ( Map.Entry<Object, Object> entry : this.http.getHttpClientParameters().entrySet() )
            {
                if ( entry.getValue() != null )
                {
                    System.setProperty( entry.getKey().toString(), entry.getValue().toString() );
                }
            }
        }

        // Some web servers don't allow the default user-agent sent by httpClient
        System.setProperty( HttpMethodParams.USER_AGENT, "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" );
        this.cl.getParams().setParameter( HttpMethodParams.USER_AGENT,
                                          "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" );

        String link = lvi.getLink();
        String anchor = "";
        int idx = link.indexOf( '#' );
        if ( idx != -1 )
        {
            anchor = link.substring( idx + 1 );
            link = link.substring( 0, idx );
        }

        try
        {
            if ( link.startsWith( "/" ) )
            {
                if ( getBaseURL() == null )
                {
                    if ( LOG.isWarnEnabled() )
                    {
                        LOG.warn( "Cannot check link [" + link + "] in page [" + lvi.getSource()
                            + "], as no base URL has been set!" );
                    }

                    return new LinkValidationResult( LinkcheckFileResult.WARNING_LEVEL, false,
                                                     "No base URL specified" );
                }

                link = getBaseURL() + link;
            }

            HttpMethod hm = null;
            try
            {
                hm = checkLink( link, 0 );
            }
            catch ( Throwable t )
            {
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( "Received: [" + t + "] for [" + link + "] in page [" + lvi.getSource() + "]", t );
                }

                return new LinkValidationResult( LinkcheckFileResult.ERROR_LEVEL, false, t.getClass().getName()
                    + " : " + t.getMessage() );
            }

            if ( hm == null )
            {
                return new LinkValidationResult( LinkcheckFileResult.ERROR_LEVEL, false,
                                                 "Cannot retreive HTTP Status" );
            }

            if ( hm.getStatusCode() == HttpStatus.SC_OK )
            {
                // lets check if the anchor is present
                if ( anchor.length() > 0 )
                {
                    String content = hm.getResponseBodyAsString();

                    if ( !Anchors.matchesAnchor( content, anchor ) )
                    {
                        return new HTTPLinkValidationResult( LinkcheckFileResult.VALID_LEVEL, false,
                            "Missing anchor '" + anchor + "'" );
                    }
                }
                return new HTTPLinkValidationResult( LinkcheckFileResult.VALID_LEVEL, true, hm.getStatusCode(),
                                                     hm.getStatusText() );
            }

            String msg =
                "Received: [" + hm.getStatusCode() + "] for [" + link + "] in page [" + lvi.getSource() + "]";
            // If there's a redirection ... add a warning
            if ( hm.getStatusCode() == HttpStatus.SC_MOVED_PERMANENTLY
                || hm.getStatusCode() == HttpStatus.SC_MOVED_TEMPORARILY
                || hm.getStatusCode() == HttpStatus.SC_TEMPORARY_REDIRECT )
            {
                LOG.warn( msg );

                return new HTTPLinkValidationResult( LinkcheckFileResult.WARNING_LEVEL, true, hm.getStatusCode(),
                                                     hm.getStatusText() );
            }

            LOG.debug( msg );

            return new HTTPLinkValidationResult( LinkcheckFileResult.ERROR_LEVEL, false, hm.getStatusCode(),
                                                 hm.getStatusText() );
        }
        catch ( Throwable t )
        {
            String msg = "Received: [" + t + "] for [" + link + "] in page [" + lvi.getSource() + "]";
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg, t );
            }
            else
            {
                LOG.error( msg );
            }

            return new LinkValidationResult( LinkcheckFileResult.ERROR_LEVEL, false, t.getMessage() );
        }
        finally
        {
            System.getProperties().remove( HttpMethodParams.USER_AGENT );

            if ( this.http.getHttpClientParameters() != null )
            {
                for ( Map.Entry<Object, Object> entry : this.http.getHttpClientParameters().entrySet() )
                {
                    if ( entry.getValue() != null )
                    {
                        System.getProperties().remove( entry.getKey().toString() );
                    }
                }
            }
        }
    }

    /** Initialize the HttpClient. */
    private void initHttpClient()
    {
        LOG.debug( "A new HttpClient instance is needed ..." );

        this.cl = new HttpClient( new MultiThreadedHttpConnectionManager() );

        // Default params
        if ( this.http.getTimeout() != 0 )
        {
            this.cl.getHttpConnectionManager().getParams().setConnectionTimeout( this.http.getTimeout() );
            this.cl.getHttpConnectionManager().getParams().setSoTimeout( this.http.getTimeout() );
        }
        this.cl.getParams().setBooleanParameter( HttpClientParams.ALLOW_CIRCULAR_REDIRECTS, true );

        HostConfiguration hc = new HostConfiguration();

        HttpState state = new HttpState();
        if ( StringUtils.isNotEmpty( this.http.getProxyHost() ) )
        {
            hc.setProxy( this.http.getProxyHost(), this.http.getProxyPort() );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( "Proxy Host:" + this.http.getProxyHost() );
                LOG.debug( "Proxy Port:" + this.http.getProxyPort() );
            }

            if ( StringUtils.isNotEmpty( this.http.getProxyUser() ) && this.http.getProxyPassword() != null )
            {
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( "Proxy User:" + this.http.getProxyUser() );
                }

                Credentials credentials;
                if ( StringUtils.isNotEmpty( this.http.getProxyNtlmHost() ) )
                {
                    credentials =
                        new NTCredentials( this.http.getProxyUser(), this.http.getProxyPassword(),
                                           this.http.getProxyNtlmHost(), this.http.getProxyNtlmDomain() );
                }
                else
                {
                    credentials =
                        new UsernamePasswordCredentials( this.http.getProxyUser(), this.http.getProxyPassword() );
                }

                state.setProxyCredentials( AuthScope.ANY, credentials );
            }
        }
        else
        {
            LOG.debug( "Not using a proxy" );
        }

        this.cl.setHostConfiguration( hc );
        this.cl.setState( state );

        LOG.debug( "New HttpClient instance created." );
    }

    /**
     * Checks the given link.
     *
     * @param link the link to check.
     * @param nbRedirect the number of current redirects.
     * @return HttpMethod
     * @throws IOException if something goes wrong.
     */
    private HttpMethod checkLink( String link, int nbRedirect )
        throws IOException
    {
        int max = MAX_NB_REDIRECT;
        if ( this.http.getHttpClientParameters() != null
            && this.http.getHttpClientParameters().get( HttpClientParams.MAX_REDIRECTS ) != null )
        {
            try
            {
                max =
                    Integer.valueOf(
                                     this.http.getHttpClientParameters().get( HttpClientParams.MAX_REDIRECTS )
                                              .toString() ).intValue();
            }
            catch ( NumberFormatException e )
            {
                if ( LOG.isWarnEnabled() )
                {
                    LOG.warn( "HttpClient parameter '" + HttpClientParams.MAX_REDIRECTS
                        + "' is not a number. Ignoring!" );
                }
            }
        }
        if ( nbRedirect > max )
        {
            throw new HttpException( "Maximum number of redirections (" + max + ") exceeded" );
        }

        HttpMethod hm;
        if ( HEAD_METHOD.equalsIgnoreCase( this.http.getMethod() ) )
        {
            hm = new HeadMethod( link );
        }
        else if ( GET_METHOD.equalsIgnoreCase( this.http.getMethod() ) )
        {
            hm = new GetMethod( link );
        }
        else
        {
            if ( LOG.isErrorEnabled() )
            {
                LOG.error( "Unsupported method: " + this.http.getMethod() + ", using 'get'." );
            }
            hm = new GetMethod( link );
        }

        // Default
        hm.setFollowRedirects( this.http.isFollowRedirects() );

        try
        {
            URL url = new URL( link );

            cl.getHostConfiguration().setHost( url.getHost(), url.getPort(), url.getProtocol() );

            cl.executeMethod( hm );

            StatusLine sl = hm.getStatusLine();
            if ( sl == null )
            {
                if ( LOG.isErrorEnabled() )
                {
                    LOG.error( "Unknown error validating link : " + link );
                }

                return null;
            }

            if ( hm.getStatusCode() == HttpStatus.SC_MOVED_PERMANENTLY
                || hm.getStatusCode() == HttpStatus.SC_MOVED_TEMPORARILY
                || hm.getStatusCode() == HttpStatus.SC_TEMPORARY_REDIRECT )
            {
                Header locationHeader = hm.getResponseHeader( "location" );

                if ( locationHeader == null )
                {
                    LOG.error( "Site sent redirect, but did not set Location header" );

                    return hm;
                }

                String newLink = locationHeader.getValue();

                // Be careful to absolute/relative links
                if ( !newLink.startsWith( "http://" ) && !newLink.startsWith( "https://" ) )
                {
                    if ( newLink.startsWith( "/" ) )
                    {
                        URL oldUrl = new URL( link );

                        newLink =
                            oldUrl.getProtocol() + "://" + oldUrl.getHost()
                                + ( oldUrl.getPort() > 0 ? ":" + oldUrl.getPort() : "" ) + newLink;
                    }
                    else
                    {
                        newLink = link + newLink;
                    }
                }

                HttpMethod oldHm = hm;

                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( "[" + link + "] is redirected to [" + newLink + "]" );
                }

                oldHm.releaseConnection();

                hm = checkLink( newLink, nbRedirect + 1 );

                // Restore the hm to "Moved permanently" | "Moved temporarily" | "Temporary redirect"
                // if the new location is found to allow us to report it
                if ( hm.getStatusCode() == HttpStatus.SC_OK && nbRedirect == 0 )
                {
                    return oldHm;
                }
            }

        }
        finally
        {
            hm.releaseConnection();
        }

        return hm;
    }
}
