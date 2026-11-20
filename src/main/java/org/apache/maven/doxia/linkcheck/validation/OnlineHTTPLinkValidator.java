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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.CredentialsStore;
import org.apache.hc.client5.http.auth.NTCredentials;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpHead;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.util.Timeout;
import org.apache.maven.doxia.linkcheck.HttpBean;
import org.apache.maven.doxia.linkcheck.model.LinkcheckFileResult;
import org.codehaus.plexus.util.StringUtils;

/**
 * Checks links which are normal URLs.
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

    /** The http bean encapsulating all http parameters supported. */
    private HttpBean http;

    /** The base URL for links that start with '/'. */
    private String baseURL;

    /** The HttpClient. */
    private transient HttpClient cl;

    /**
     * Constructor: initialize settings, use HEAD method.
     */
    public OnlineHTTPLinkValidator()
    {
        this( new HttpBean() );
    }

    /**
     * Constructor: initialize settings.
     *
     * @param bean the http bean encapsulating all HTTP parameters supported
     */
    public OnlineHTTPLinkValidator( HttpBean bean )
    {
        if ( bean == null )
        {
            bean = new HttpBean();
        }

        LOG.debug( "Using method : [" + bean.getMethod() + "]" );

        this.http = bean;

        initHttpClient();
    }

    /**
     * The base URL.
     *
     * @return the base URL
     */
    public String getBaseURL()
    {
        return this.baseURL;
    }

    /**
     * Sets the base URL. This is pre-pended to links that start with '/'.
     *
     * @param url the base URL
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
                    LOG.warn( "Cannot check link [" + link + "] in page [" + lvi.getSource()
                            + "], as no base URL has been set!" );

                    return new LinkValidationResult( LinkcheckFileResult.WARNING_LEVEL, false,
                                                     "No base URL specified" );
                }

                link = getBaseURL() + link;
            }

            HttpResponseInfo response;
            try
            {
                response = checkLink( link, 0, anchor.length() > 0 );
            }
            catch ( IOException | HttpException ex )
            {
                LOG.debug( "Received: [" + ex + "] for [" + link + "] in page [" + lvi.getSource() + "]", ex );

                return new LinkValidationResult( LinkcheckFileResult.ERROR_LEVEL, false, ex.getClass().getName()
                    + " : " + ex.getMessage() );
            }

            int statusCode = response.getStatusCode();
            if ( statusCode == HttpStatus.SC_OK )
            {
                // check if the anchor is present
                if ( anchor.length() > 0 )
                {
                    String content = response.getContent();

                    if ( !Anchors.matchesAnchor( content, anchor ) )
                    {
                        return new HTTPLinkValidationResult( LinkcheckFileResult.VALID_LEVEL, false,
                            "Missing anchor '" + anchor + "'" );
                    }
                }
                return new HTTPLinkValidationResult( LinkcheckFileResult.VALID_LEVEL, true,
                        statusCode, response.getReasonPhrase() );
            }

            String msg = "Received: [" + statusCode + "] for [" + link + "] in page ["
                    + lvi.getSource() + "]";
            // If there's a redirection, add a warning
            if ( statusCode == HttpStatus.SC_MOVED_PERMANENTLY
                || statusCode == HttpStatus.SC_MOVED_TEMPORARILY
                || statusCode == HttpStatus.SC_TEMPORARY_REDIRECT )
            {
                LOG.warn( msg );

                return new HTTPLinkValidationResult( LinkcheckFileResult.WARNING_LEVEL, true, statusCode,
                        response.getReasonPhrase() );
            }

            LOG.debug( msg );

            return new HTTPLinkValidationResult( LinkcheckFileResult.ERROR_LEVEL, false, statusCode,
                    response.getReasonPhrase() );
        }
        finally
        {
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
        LOG.debug( "Creating a new HttpClient instance." );

        HttpClientBuilder builder = HttpClients.custom();

        // connection manager
        PoolingHttpClientConnectionManagerBuilder connectionManagerBuilder =
            PoolingHttpClientConnectionManagerBuilder.create()
                .setMaxConnTotal( 100 )
                .setMaxConnPerRoute( 10 );

        RequestConfig.Builder requestConfigBuilder = RequestConfig.custom();
        // redirects
        requestConfigBuilder.setRedirectsEnabled( this.http.isFollowRedirects() );

        // timeouts: in HttpClient 5 socket timeouts belong to the connection configuration
        if ( this.http.getTimeout() != 0 )
        {
            Timeout timeout = Timeout.ofMilliseconds( this.http.getTimeout() );
            requestConfigBuilder.setConnectTimeout( timeout );
            connectionManagerBuilder.setDefaultConnectionConfig( ConnectionConfig.custom()
                    .setConnectTimeout( timeout )
                    .setSocketTimeout( timeout )
                    .build() );
        }

        builder.setConnectionManager( connectionManagerBuilder.build() );
        builder.setDefaultRequestConfig( requestConfigBuilder.build() );

        // proxy
        if ( StringUtils.isNotBlank( this.http.getProxyHost() ) )
        {
            HttpHost proxy = new HttpHost( this.http.getProxyHost(), this.http.getProxyPort() );
            requestConfigBuilder.setProxy( proxy );
            LOG.debug( "Proxy Host:" + this.http.getProxyHost() );
            LOG.debug( "Proxy Port:" + this.http.getProxyPort() );

            if ( StringUtils.isNotEmpty( this.http.getProxyUser() ) && this.http.getProxyPassword() != null )
            {
                LOG.debug( "Proxy User:" + this.http.getProxyUser() );

                Credentials credentials;
                if ( StringUtils.isNotEmpty( this.http.getProxyNtlmHost() ) )
                {
                    credentials = new NTCredentials( this.http.getProxyUser(),
                            this.http.getProxyPassword().toCharArray(),
                            this.http.getProxyNtlmHost(), this.http.getProxyNtlmDomain() );
                }
                else
                {
                    credentials =
                        new UsernamePasswordCredentials( this.http.getProxyUser(),
                                                         this.http.getProxyPassword().toCharArray() );
                }
                CredentialsStore credentialsProvider = new BasicCredentialsProvider();
                credentialsProvider.setCredentials( new AuthScope( null, null, -1, null, null ), credentials );
                builder.setDefaultCredentialsProvider( credentialsProvider );
            }
        }

        this.cl = builder.build();

        LOG.debug( "New HttpClient instance created." );
    }

    /**
     * Checks the given link.
     *
     * @param url the link to check
     * @param nbRedirect the number of current redirects
     * @param readEntity whether the response body is needed to check an anchor
     * @return the response details needed by the caller
     * @throws IOException if something goes wrong
     * @throws HttpException if the URL or the redirect chain is invalid
     */
    private HttpResponseInfo checkLink( String url, int nbRedirect, boolean readEntity )
            throws IOException, HttpException
    {

        // check if we've redirected too many times
        int max = MAX_NB_REDIRECT;
        if ( this.http.getHttpClientParameters() != null
            && this.http.getHttpClientParameters().get( "http.protocol.max-redirects" ) != null )
        {
            try
            {
                max = Integer.parseInt(
                        this.http.getHttpClientParameters().get( "http.protocol.max-redirects" ).toString() );
            }
            catch ( NumberFormatException e )
            {
                LOG.warn( "HttpClient parameter '" + "http.protocol.max-redirects"
                        + "' is not a number. Ignoring!" );
            }
        }
        if ( nbRedirect > max )
        {
            throw new HttpException( "Maximum number of redirections (" + max + ") exceeded" );
        }

        ClassicHttpRequest request;
        try
        {
            if ( "HEAD".equalsIgnoreCase( this.http.getMethod() ) )
            {
                request = new HttpHead( url );
            }
            else if ( "GET".equalsIgnoreCase( this.http.getMethod() ) )
            {
                request = new HttpGet( url );
            }
            else
            {
                LOG.error( "Unsupported method: " + this.http.getMethod() + ", using 'get'." );
                request = new HttpGet( url );
            }
        }
        catch ( IllegalArgumentException ex )
        {
            throw new HttpException( "Invalid URL " + url, ex );
        }

        // The response handler closes the response automatically in HttpClient 5.
        HttpResponseInfo response = cl.execute( request, httpResponse ->
            {
                String content = null;
                if ( readEntity && httpResponse.getCode() == HttpStatus.SC_OK
                    && httpResponse.getEntity() != null )
                {
                    content = EntityUtils.toString( httpResponse.getEntity() );
                }
                Header locationHeader = httpResponse.getFirstHeader( "location" );
                return new HttpResponseInfo( httpResponse.getCode(), httpResponse.getReasonPhrase(), content,
                                             locationHeader != null ? locationHeader.getValue() : null );
            } );

        int statusCode = response.getStatusCode();
        if ( statusCode == HttpStatus.SC_MOVED_PERMANENTLY
                || statusCode == HttpStatus.SC_MOVED_TEMPORARILY
                || statusCode == HttpStatus.SC_TEMPORARY_REDIRECT )
        {
            if ( response.getLocation() == null )
            {
                LOG.error( "Site sent redirect, but did not set Location header" );
                return response;
            }

            String newLink = response.getLocation();

            // Be careful to absolute/relative links
            if ( !newLink.startsWith( "http://" ) && !newLink.startsWith( "https://" ) )
            {
                if ( newLink.startsWith( "/" ) )
                {
                    URL oldUrl = new URL( url );
                    newLink = oldUrl.getProtocol() + "://" + oldUrl.getHost()
                            + ( oldUrl.getPort() > 0 ? ":" + oldUrl.getPort() : "" ) + newLink;
                }
                else
                {
                    newLink = url + newLink;
                }
            }

            LOG.debug( "[" + url + "] is redirected to [" + newLink + "]" );

            HttpResponseInfo oldResponse = response;
            response = checkLink( newLink, nbRedirect + 1, readEntity );

            // Restore the status to "Moved permanently" | "Moved temporarily" | "Temporary redirect"
            // if the new location is found to allow us to report it
            if ( statusCode == HttpStatus.SC_OK && nbRedirect == 0 )
            {
                return oldResponse;
            }
        }
        return response;
    }

    /** Immutable snapshot of the response fields used after the response has been closed. */
    private static final class HttpResponseInfo
    {
        private final int statusCode;

        private final String reasonPhrase;

        private final String content;

        private final String location;

        HttpResponseInfo( int statusCode, String reasonPhrase, String content, String location )
        {
            this.statusCode = statusCode;
            this.reasonPhrase = reasonPhrase;
            this.content = content;
            this.location = location;
        }

        int getStatusCode()
        {
            return statusCode;
        }

        String getReasonPhrase()
        {
            return reasonPhrase;
        }

        String getContent()
        {
            return content;
        }

        String getLocation()
        {
            return location;
        }
    }
}
