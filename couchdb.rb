# -*- coding: utf-8 -*-
#
#== Original License
# The original "Couch" module comes from the couchdb wiki at;
#
#   http://wiki.apache.org/couchdb/Getting_started_with_Ruby
#
# Please refer the original code named couchdb.rb.orig in the same directory.
#
#== License of my part
# Part of my code is licensed by; 
#
#  Copyright (C) 2010,2011 Yasuhiro ABE <yasu@yasundial.org>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

require 'net/https'
module Couch

  class Server
    def initialize(host, port, options = nil)
      @host = host
      @port = port
      @options = options
      @options = Hash.new if options.nil? or not options.kind_of?(Hash)
      @www_auth = nil
      @auth = nil
      if options.has_key?('digest_auth')
        require 'net/http/digest_auth'
        @digest_auth = Net::HTTP::DigestAuth.new
      end
    end

    def delete(uri)
      setup_digest_auth(uri,'DELETE')
      request(Net::HTTP::Delete.new(uri))
    end

    def get(uri)
      setup_digest_auth(uri,'GET')
      request(Net::HTTP::Get.new(uri))
    end

    def put(uri, json)
      setup_digest_auth(uri,'PUT')
      req = Net::HTTP::Put.new(uri)
      req["content-type"] = "application/json"
      req.body = json
      request(req)
    end

    def post(uri, json)
      setup_digest_auth(uri,'POST')
      req = Net::HTTP::Post.new(uri)
      req["content-type"] = "application/json"
      req.body = json
      request(req)
    end

    def check_ssl(client)
      if @options.has_key?('cacert')
        client.use_ssl = true
        client.ca_file = @options['cacert']
        client.verify_mode  = OpenSSL::SSL::VERIFY_PEER
        client.verify_mode  = @options['ssl_verify_mode'] if @options.has_key?('ssl_verify_mode')
        client.verify_depth = 5
        client.verify_depth = @options['ssl_verify_depth'] if @options.has_key?('ssl_verify_depth')
        client.cert         = @options['ssl_client_cert'] if @options.has_key?('ssl_client_cert')
        client.key          = @options['ssl_client_key'] if @options.has_key?('ssl_client_key')
      end
    end

    def request(req)
      req.basic_auth @options['user'], @options['password'] if @options.has_key?('user') and 
        @options.has_key?('password') and 
        not @options.has_key?('digest_auth')
      req["X-Auth-CouchDB-UserName"] = @options['proxy_auth_user'] if @options.has_key?('proxy_auth_user')
      req["X-Auth-CouchDB-Roles"] = @options['proxy_auth_roles'] if @options.has_key?('proxy_auth_roles')
      req["X-Auth-CouchDB-Token"] = @options['proxy_auth_token'] if @options.has_key?('proxy_auth_token')
      
      client = Net::HTTP.new(@host, @port)
      check_ssl(client)
      
      if @options.has_key?('digest_auth')
        req["Authorization"] = @auth
      end
      
      res = client.start { |http| http.request(req) }
      @www_auth = nil if res.kind_of?(Net::HTTPUnauthorized) and @options.has_key?('digest_auth')
      res
    end
    
    private

    def setup_digest_auth(uri, method)
      return if not @options.has_key?('digest_auth')
      if @www_auth == nil
        req = Net::HTTP::Get.new(uri)
        client = Net::HTTP.new(@host, @port)
        check_ssl(client)
        res = client.start { |http| http.request(req) }
        ## res must be the instance of Net::HTTPUnauthorized
        raise res if not res.kind_of?(Net::HTTPUnauthorized)
        @www_auth = res['www-authenticate']
      end
      url = TinyURI.new(@options['user'], @options['password'], uri)
      @auth = @digest_auth.auth_header(url, @www_auth, method)
    end
  end

  private
  # net/http/digest_auth using this class to pass information.
  class TinyURI  # :nodoc:all
    attr_accessor :request_uri, :user, :password
    def initialize(user, pass, path)
      @user = user 
      @password = pass
      @request_uri = path
    end
  end
end
