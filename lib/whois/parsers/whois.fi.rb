#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.fi.rb'


module Whois
  class Parsers

    # Parser for the whois.fi server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisFi < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisFi


      property_not_supported :disclaimer

      property_supported :domain do
        node("domain")
      end

      property_not_supported :domain_id


      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!node("status:available")
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("created") { |value| parse_time(value) }
      end

      property_supported :updated_on do
        node("modified") { |value| parse_time(value) }
      end

      property_supported :expires_on do
        node("expires") { |value| parse_time(value) }
      end

      property_supported :nameservers do
        Array.wrap(node("nserver")).map do |line|
          Parser::Nameserver.new(name: line.split(" ").first)
        end
      end

      property_not_supported :registrar
      property_not_supported :registrant_contacts
      property_not_supported :admin_contacts
      property_not_supported :technical_contacts



      # NEWPROPERTY
      def reserved?
        !!content_for_scanner.match(/Domain not available/)
      end

    end

  end
end
