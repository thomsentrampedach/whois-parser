#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'

module Whois
  class Parsers

    # Parser for the whois.gg server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisGg < Base

      property_supported :domain do
        node('Domain').first
      end

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /NOT FOUND/)
      end

      property_supported :registered? do
        !available?
      end

      property_supported :nameservers do
        node('Name servers').map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end

      property_not_supported :domain_id
      property_not_supported :created_on
      property_not_supported :updated_on
      property_not_supported :expires_on
      property_not_supported :registrant_contacts
      property_not_supported :admin_contacts
      property_not_supported :technical_contacts
      property_not_supported :registrar

      private

      def node(key)
        content_for_scanner
          .scan(/#{key}:\n\s*(.+?)\n\s*?\n/m)
          .flatten
          .map { |a| a.split("\n") }
          .flatten
          .map(&:strip)
          .compact
      end
    end

  end
end
